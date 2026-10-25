'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawn } = require('child_process');
const flow = require('../tools/flow');
const evaluation = require('../tools/evaluation-harness');
const { contextEnv, resolveKnowledgeContext } = require('../tools/lib/path-context');
const { registerWorkspace, readTeamFlowStatus } = require('../tools/lib/team-store');
const supported = ['linux', 'win32'].includes(process.platform);
const policy = { workMs: 20000, setupMs: 10000, cleanupMs: 10000, progressMs: 0 };
const files = ['sync-tracked.js', 'build-wiki-graph.js', 'lint-wiki.js', 'external-memory-status.js', 'build-routing-bundle.js',
  'build-search-index.js', 'scan-secrets.js', 'doctor.js', 'build-visual-inspector.js', 'collect-metrics.js', 'generate-pr-summary.js', 'render-graph-execution.js', 'apply-template.js'];
function seed(team = false) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'owned-flow-')), system = path.join(root, '.knowledge');
  fs.mkdirSync(path.join(system, 'tools'), { recursive: true });
  fs.writeFileSync(path.join(system, 'config.yaml'), 'updates:\n  enabled: false\n');
  fs.writeFileSync(path.join(system, 'package.json'), '{"version":"3.4.4"}');
  for (const name of files) fs.writeFileSync(path.join(system, 'tools', name), 'console.log(JSON.stringify({status:"ok"}));\n');
  const context = resolveKnowledgeContext({ __skipCli: true, mode: team ? 'team' : 'repo', systemRoot: system, targetRoot: root, projectKnowledgeRoot: system,
    ...(team ? { teamRoot: path.join(root, 'team'), workspaceId: 'workspace', agentId: 'owned-flow-test' } : {}) });
  if (team) registerWorkspace(context);
  return { root, system, context, cleanup: () => fs.rmSync(root, { recursive: true, force: true }) };
}
test('ordinary Flow runs all steps, binds its full evidence log and drains before success', { skip: !supported }, async () => {
  const f = seed();
  try {
    const out = await flow.runFlowAsync({ name: 'doctor', context: f.context, json: true, quiet: true }, { budgets: policy });
    assert.equal(out.status, 'ok', JSON.stringify(out)); assert.equal(out.steps_total, 8); assert.equal(out.steps_ok, 8);
    assert.equal(out.flow_log_status, 'written'); assert.equal(out.ownership.cleanup.status, 'completed');
    assert.equal(fs.readFileSync(path.resolve(f.root, out.flow_log)).length, out.flow_log_bytes);
  } finally { f.cleanup(); }
});
test('evaluation runs its real producer path with a separate state root and native cleanup', { skip: !supported }, async () => {
  const f = seed(); const state = path.join(f.root, 'state'); fs.mkdirSync(state);
  try {
    const out = await evaluation.mainAsync({ budgets: policy, env: contextEnv({ ...f.context, stateRoot: state }) });
    assert.equal(out.status, 'release_candidate', JSON.stringify(out)); assert.equal(out.results.length, 11); assert.equal(out.failed_count, 0);
    assert.equal(out.command_cleanup.status, 'completed'); assert.equal(out.ownership.cleanup.status, 'completed');
    const persisted = JSON.parse(fs.readFileSync(path.join(state, 'evaluation/results/latest.json')));
    assert.equal(persisted.results.length, 11);
    assert.equal(persisted.command_cleanup.status, 'completed'); assert.equal(persisted.command_authority_cleanup.status, 'completed');
    assert.equal(fs.existsSync(path.join(f.system, 'evaluation/results/latest.json')), false);
  } finally { f.cleanup(); }
});
test('Team Flow publishes scope before command admission and releases after drain', { skip: !supported }, async () => {
  const f = seed(true);
  try {
    const env = contextEnv(f.context);
    const { value: out } = await flow.mainAsync(['doctor', '--exclusive', '--json'], { budgets: policy, env });
    assert.equal(out.overall_status, 'ok', JSON.stringify(out));
    assert.deepEqual(out.team_release, { status: 'released' });
    assert.equal(out.command_cleanup.status, 'completed'); assert.equal(out.ownership.cleanup.status, 'completed');
    assert.equal(readTeamFlowStatus(f.context.teamRoot, f.context.repoId, f.context.workspaceId, out.run_id).last_status, 'ok');
  } finally { f.cleanup(); }
});
test('an actual admitted Flow can be cancelled while a command performs unending work', { skip: !supported }, async () => {
  const f = seed(), marker = path.join(f.root, 'admitted'), controller = new AbortController();
  fs.writeFileSync(path.join(f.system, 'tools/sync-tracked.js'), `require('fs').writeFileSync(${JSON.stringify(marker)},'started');for(;;){}`);
  let timer;
  try {
    timer = setInterval(() => { if (fs.existsSync(marker)) controller.abort(); }, 10);
    await assert.rejects(flow.runFlowAsync({ name: 'doctor', context: f.context, json: true }, { budgets: policy, signal: controller.signal }), error => {
      assert.equal(error.code, 'command_cancelled'); assert.equal(error.cleanup.status, 'completed'); return true;
    });
    assert.equal(fs.existsSync(marker), true); assert.equal(fs.existsSync(path.join(f.system, 'maintenance/flow-logs')), false);
  } finally { clearInterval(timer); f.cleanup(); }
});
async function waitFile(file, timeout = 10000) {
  const deadline = performance.now() + timeout;
  while (!fs.existsSync(file)) {
    if (performance.now() >= deadline) throw new Error(`Marker was not published: ${file}`);
    await new Promise(resolve => setTimeout(resolve, 10));
  }
}
test('a new Team Flow recovers the exact old scope after SIGKILL of the CLI controller', { skip: process.platform !== 'linux' }, async () => {
  const f = seed(true), marker = path.join(f.root, 'admitted');
  fs.writeFileSync(path.join(f.system, 'tools/sync-tracked.js'), `require('fs').writeFileSync(${JSON.stringify(marker)},'started');setInterval(()=>{},1000);`);
  const child = spawn(process.execPath, [path.join(__dirname, '../tools/flow.js'), 'doctor', '--exclusive', '--json', '--work-timeout-ms=20000', '--cleanup-timeout-ms=10000'],
    { env: contextEnv(f.context), stdio: ['ignore', 'pipe', 'pipe'] });
  let diagnostics = ''; child.stdout.on('data', chunk => { diagnostics += chunk; }); child.stderr.on('data', chunk => { diagnostics += chunk; });
  try {
    await waitFile(marker);
    const exited = new Promise(resolve => child.once('exit', resolve)); child.kill('SIGKILL'); await exited;
    fs.writeFileSync(path.join(f.system, 'tools/sync-tracked.js'), 'console.log(JSON.stringify({status:"ok"}));\n');
    const { value: next } = await flow.mainAsync(['doctor', '--exclusive', '--json'], { budgets: policy, env: contextEnv(f.context) });
    assert.equal(next.overall_status, 'ok', JSON.stringify({ next, diagnostics }));
    assert.equal(next.team_release.status, 'released'); assert.equal(next.command_cleanup.status, 'completed');
  } finally {
    if (child.exitCode === null && child.signalCode === null) {
      const exited = new Promise(resolve => child.once('exit', resolve)); child.kill('SIGKILL'); await exited;
    }
    f.cleanup();
  }
});
test('concurrent Team Flow cannot execute any command before the first scope drains and releases', { skip: !supported }, async () => {
  const f = seed(true), marker = path.join(f.root, 'first-admitted'), gate = path.join(f.root, 'continue'), events = path.join(f.root, 'commands.ndjson');
  for (const name of files) fs.writeFileSync(path.join(f.system, 'tools', name),
    `const fs=require('fs');const tag=process.env.KNOWLEDGE_TEST_RUN;const finish=()=>{fs.appendFileSync(${JSON.stringify(events)},JSON.stringify({tag,file:${JSON.stringify(name)}})+'\\n');console.log(JSON.stringify({status:'ok'}));};` +
    (name === 'sync-tracked.js' ? `if(tag==='first'){fs.writeFileSync(${JSON.stringify(marker)},'started');const timer=setInterval(()=>{if(fs.existsSync(${JSON.stringify(gate)})){clearInterval(timer);finish();}},10);}else finish();` : 'finish();'));
  const firstAbort = new AbortController(), secondAbort = new AbortController();
  let first, second;
  try {
    first = flow.mainAsync(['doctor', '--exclusive', '--json'], { budgets: policy, signal: firstAbort.signal, env: contextEnv(f.context, { KNOWLEDGE_TEST_RUN: 'first' }) });
    first.catch(() => {});
    await waitFile(marker);
    second = flow.mainAsync(['doctor', '--exclusive', '--json'], { budgets: policy, signal: secondAbort.signal, env: contextEnv(f.context, { KNOWLEDGE_TEST_RUN: 'second' }) });
    second.catch(() => {});
    await new Promise(resolve => setTimeout(resolve, 300));
    assert.equal(fs.existsSync(events), false, 'The second flow executed while the first retained its Team scope');
    fs.writeFileSync(gate, 'go');
    const [a, b] = await Promise.all([first, second]);
    assert.equal(a.value.overall_status, 'ok', JSON.stringify(a.value)); assert.equal(b.value.overall_status, 'ok', JSON.stringify(b.value));
    const records = fs.readFileSync(events, 'utf8').trim().split('\n').map(JSON.parse);
    assert.deepEqual(records.map(row => row.tag), [...Array(8).fill('first'), ...Array(8).fill('second')]);
  } finally {
    firstAbort.abort(); secondAbort.abort();
    await Promise.allSettled([first, second].filter(Boolean));
    f.cleanup();
  }
});
