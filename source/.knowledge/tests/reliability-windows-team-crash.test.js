'use strict';
// Actual Windows custody outside the ancestor Job, not a POSIX approximation.
const test = require('node:test'), assert = require('node:assert/strict');
const fs = require('fs'), os = require('os'), path = require('path');
const { spawn } = require('child_process');
assert.equal(process.platform, 'win32', 'This gate requires physical Windows Job Objects');
const runner = require('../tools/lib/command-runner'), flow = require('../tools/flow');
const proof = require('../tools/lib/command-scope-proof');
const { contextEnv, resolveKnowledgeContext } = require('../tools/lib/path-context');
const { registerWorkspace, lockPath } = require('../tools/lib/team-store');
const policy = { workMs: 120000, setupMs: 60000, cleanupMs: 60000, progressMs: 0 };
const files = ['sync-tracked.js', 'build-wiki-graph.js', 'lint-wiki.js', 'external-memory-status.js', 'build-routing-bundle.js',
  'build-search-index.js', 'scan-secrets.js', 'doctor.js', 'build-visual-inspector.js', 'collect-metrics.js', 'generate-pr-summary.js'];
function seed() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'windows-team-crash-')), system = path.join(root, '.knowledge');
  fs.mkdirSync(path.join(system, 'tools'), { recursive: true });
  fs.writeFileSync(path.join(system, 'config.yaml'), 'updates:\n  enabled: false\n');
  fs.writeFileSync(path.join(system, 'package.json'), '{"version":"3.4.4"}');
  for (const file of files) fs.writeFileSync(path.join(system, 'tools', file), 'console.log(JSON.stringify({status:"ok"}));\n');
  const context = resolveKnowledgeContext({ __skipCli: true, mode: 'team', systemRoot: system, targetRoot: root,
    projectKnowledgeRoot: system, teamRoot: path.join(root, 'team'), workspaceId: 'workspace', agentId: 'windows-crash-test' });
  registerWorkspace(context);
  const marker = path.join(root, 'command-admitted');
  fs.writeFileSync(path.join(system, 'tools/sync-tracked.js'),
    `require('fs').writeFileSync(${JSON.stringify(marker)},'started');setInterval(()=>{},1000);`);
  return { root, system, context, marker };
}
async function until(predicate, allowance = 120000) {
  const start = runner.mono();
  while (!predicate()) {
    if (runner.mono() - start >= allowance) throw new Error('Native admission/recovery boundary was not observed');
    await runner.delay(10);
  }
}
function boundScope(f) {
  const directory = lockPath(f.context.teamRoot, f.context.repoId);
  const owner = JSON.parse(fs.readFileSync(path.join(directory, 'owner.json')));
  const scope = JSON.parse(fs.readFileSync(path.join(directory, 'execution-scope.json')));
  assert.equal(proof.validateExecutionScope(scope), true);
  assert.equal(scope.backend, 'windows_job_object');
  assert.equal(scope.descriptor.schema_version, 'knowledge-windows-command-job.v2');
  assert.ok(owner.execution_scope && scope.descriptor.secondary);
  return scope;
}
async function terminal(scope) {
  let observed;
  try { await until(() => { observed = proof.queryScopeClosure(scope, { timeoutMs: 20000 }); return observed.status === 'completed'; }, 60000); }
  catch (error) { error.message += ': ' + JSON.stringify({ last_observation: observed,
    receipt_files: (() => { try { return fs.readdirSync(scope.descriptor.receipt_store.directory); } catch (cause) { return { code: cause.code }; } })() }); throw error; }
  assert.equal(observed.active_processes, 0); assert.equal(observed.root_exited, true);
  assert.equal(observed.basis, 'signed_terminal_receipt');
  return observed;
}
async function newFlow(f) {
  fs.writeFileSync(path.join(f.system, 'tools/sync-tracked.js'), 'console.log(JSON.stringify({status:"ok"}));\n');
  const { value } = await flow.mainAsync(['doctor', '--exclusive', '--json'], { budgets: policy, env: contextEnv(f.context) });
  assert.equal(value.overall_status, 'ok', JSON.stringify(value));
  assert.equal(value.team_release.status, 'released');
  assert.equal(value.command_cleanup.status, 'completed'); assert.equal(value.ownership.cleanup.status, 'completed');
  return value;
}

test('Windows original CLI crash leaves independent B custody proof and a new Team Flow recovers', { timeout: 300000 }, async t => {
  const f = seed(); let cleanable = false, oldScope;
  const traceDirectory = path.join(f.root, 'holder-trace'); fs.mkdirSync(traceDirectory);
  const child = spawn(process.execPath, ['--require', path.join(__dirname, 'helpers/reliability-windows-custody-trace.cjs'),
    path.resolve(__dirname, '../tools/flow.js'), 'doctor', '--exclusive', '--json',
    '--work-timeout-ms=120000', '--setup-timeout-ms=60000', '--cleanup-timeout-ms=60000'],
  { env: { ...contextEnv(f.context), KNOWLEDGE_QA_CUSTODY_TRACE: traceDirectory }, stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true });
  let output = ''; child.stdout.on('data', part => { if (output.length < 1048576) output += part; });
  child.stderr.on('data', part => { if (output.length < 1048576) output += part; });
  let exited = false; const observedExit = new Promise(resolve => child.once('exit', () => { exited = true; resolve(); }));
  try {
    await until(() => fs.existsSync(f.marker)); oldScope = boundScope(f);
    child.kill('SIGKILL'); await observedExit;
    const closed = await terminal(oldScope);
    const next = await newFlow(f); cleanable = true;
    t.diagnostic(JSON.stringify({ killed: 'creator_owned_original_cli', prior_scope_basis: closed.basis,
      new_flow_status: next.overall_status, native: oldScope.descriptor.native, output_bytes: Buffer.byteLength(output) }));
  } finally {
    if (!exited) { child.kill('SIGKILL'); await observedExit; }
    for (const name of fs.readdirSync(traceDirectory).filter(name => /^(?:controller|primary|secondary)-\d+\.ndjson$/.test(name))) {
      const file = path.join(traceDirectory, name);
      if (fs.statSync(file).size > 262144) { t.diagnostic(JSON.stringify({ custody_trace: name, oversized: true })); continue; }
      const rows = fs.readFileSync(file, 'utf8').trim().split('\n').filter(Boolean).map(line => { try { return JSON.parse(line); } catch { return { truncated: true }; } });
      t.diagnostic(JSON.stringify({ custody_trace: name, events: rows.slice(0, 160) }));
    }
    if (cleanable) fs.rmSync(f.root, { recursive: true, force: true });
    else t.diagnostic(JSON.stringify({ fixture_retained: true, cleanup_not_claimed: true }));
  }
});

test('Windows nested fixed Flow cancellation preserves a custodian outside every owned ancestor Job', { timeout: 300000 }, async t => {
  const f = seed(), controller = new AbortController(); let cleanable = false, pending;
  try {
    // The outer step resolves the one fixed installed Flow entrypoint. The
    // nested CLI overrides only its project/system context to this fixture.
    const context = { ...f.context, systemRoot: path.resolve(__dirname, '..') };
    assert.equal(/\s/.test(f.system), false, 'The whitespace-delimited compatibility command requires an unambiguous fixture path');
    pending = flow.runOneAsync(`flow.js doctor --exclusive --json --system-root=${f.system}`, context,
      { budgets: policy, signal: controller.signal, env: contextEnv(f.context) });
    pending.catch(() => {});
    await until(() => fs.existsSync(f.marker));
    const oldScope = boundScope(f);
    controller.abort();
    await assert.rejects(pending, error => {
      assert.equal(error.code, 'command_cancelled', JSON.stringify(error));
      assert.equal(error.cleanup?.status, 'completed', JSON.stringify(error)); return true;
    });
    const closed = await terminal(oldScope), next = await newFlow(f); cleanable = true;
    t.diagnostic(JSON.stringify({ cancellation: 'original_controller_abort_signal', nested_fixed_cli: true,
      prior_scope_basis: closed.basis, new_flow_status: next.overall_status, native: oldScope.descriptor.native }));
  } finally {
    controller.abort(); await Promise.allSettled(pending ? [pending] : []);
    if (cleanable) fs.rmSync(f.root, { recursive: true, force: true });
    else t.diagnostic(JSON.stringify({ fixture_retained: true, cleanup_not_claimed: true }));
  }
});
