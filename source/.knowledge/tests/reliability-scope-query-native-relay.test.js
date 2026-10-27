'use strict';
// Actual Linux compatibility check for the new shared query deadline. The old
// outer PID namespace is held open so the kernel cannot reuse its inode for
// the successor. The successor's real namespace is observed before permit.
// Product sources and native observations are not instrumented or substituted.
const test = require('node:test'), assert = require('node:assert/strict');
const fs = require('node:fs'), os = require('node:os'), path = require('node:path');
const { spawn } = require('node:child_process');
const source = process.env.KNOWLEDGE_SCOPE_QUERY_TEST_SOURCE || path.join(__dirname, '..');
const flow = require(path.join(source, 'tools/flow'));
const proof = require(path.join(source, 'tools/lib/command-scope-proof'));
const { contextEnv, resolveKnowledgeContext } = require(path.join(source, 'tools/lib/path-context'));
const { registerWorkspace, lockPath } = require(path.join(source, 'tools/lib/team-store'));
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));
const tick = () => Number(process.hrtime.bigint()) / 1e6;
const policy = { workMs: 20000, setupMs: 10000, cleanupMs: 10000, progressMs: 0 };
const files = ['sync-tracked.js', 'build-wiki-graph.js', 'lint-wiki.js', 'external-memory-status.js', 'build-routing-bundle.js',
  'build-search-index.js', 'scan-secrets.js', 'doctor.js', 'build-visual-inspector.js', 'collect-metrics.js', 'generate-pr-summary.js', 'render-graph-execution.js', 'apply-template.js'];

test('actual Linux new Team Flow recovers through relay with the old outer namespace inode retained',
  { skip: process.platform !== 'linux', timeout: 90000 }, async t => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'scope-query-real-relay-'));
    const system = path.join(root, '.knowledge'), marker = path.join(root, 'admitted');
    fs.mkdirSync(path.join(system, 'tools'), { recursive: true });
    fs.writeFileSync(path.join(system, 'config.yaml'), 'updates:\n  enabled: false\n');
    fs.writeFileSync(path.join(system, 'package.json'), '{"version":"3.4.4"}');
    for (const name of files) fs.writeFileSync(path.join(system, 'tools', name), 'console.log(JSON.stringify({status:"ok"}));\n');
    const context = resolveKnowledgeContext({ __skipCli: true, mode: 'team', systemRoot: system, targetRoot: root, projectKnowledgeRoot: system,
      teamRoot: path.join(root, 'team'), workspaceId: 'workspace', agentId: 'scope-query-budget-test' });
    registerWorkspace(context);
    fs.writeFileSync(path.join(system, 'tools/sync-tracked.js'), `require('fs').writeFileSync(${JSON.stringify(marker)},'started');setInterval(()=>{},1000);`);
    const child = spawn(process.execPath, [path.join(source, 'tools/flow.js'), 'doctor', '--exclusive', '--json', '--work-timeout-ms=20000', '--cleanup-timeout-ms=10000'],
      { env: contextEnv(context), stdio: ['ignore', 'pipe', 'pipe'] });
    let childExited = false, childError, output = '', oldScope, oldClosed = false, nextClosed = false, nextPromise;
    let oldNamespaceFd, nextNamespaceFd, nextNamespaceIno, oldNamespaceIno;
    const abort = new AbortController();
    child.once('exit', () => { childExited = true; });
    child.once('error', error => { childError = error; });
    child.stdout.on('data', bytes => { output = (output + bytes).slice(-65536); });
    child.stderr.on('data', bytes => { output = (output + bytes).slice(-65536); });
    async function ensureChildExit() {
      if (!childExited && !childError) child.kill('SIGKILL');
      const deadline = tick() + 10000;
      while (!childExited && !childError && tick() < deadline) await delay(10);
      return childExited;
    }
    async function observeOldClosure() {
      if (!oldScope) return false;
      const deadline = tick() + 10000;
      do {
        const observed = proof.queryScopeClosure(oldScope, { timeoutMs: Math.max(1, Math.min(1000, deadline - tick())) });
        if (observed.status === 'completed') return true;
        await delay(10);
      } while (tick() < deadline);
      return false;
    }
    t.after(async () => {
      abort.abort();
      await ensureChildExit();
      if (nextPromise) await Promise.allSettled([nextPromise]);
      if (!oldClosed) oldClosed = await observeOldClosure();
      for (const fd of [oldNamespaceFd, nextNamespaceFd]) if (fd !== undefined) fs.closeSync(fd);
      if (childExited && oldClosed && nextClosed) fs.rmSync(root, { recursive: true, force: true });
      else t.diagnostic(JSON.stringify({ fixture_retained_unconfirmed: root, childExited, oldClosed, nextClosed }));
    });
    const admissionDeadline = tick() + 10000;
    while (!fs.existsSync(marker)) {
      assert.ifError(childError);
      assert.equal(childExited, false, output);
      assert(tick() < admissionDeadline, 'Original command did not admit: ' + output);
      await delay(10);
    }
    oldScope = JSON.parse(fs.readFileSync(path.join(lockPath(context.teamRoot, context.repoId), 'execution-scope.json'), 'utf8'));
    assert.equal(proof.validateExecutionScope(oldScope), true);
    oldNamespaceFd = fs.openSync('/proc/' + oldScope.descriptor.controller.proc_pid + '/ns/pid', fs.constants.O_RDONLY);
    oldNamespaceIno = String(fs.fstatSync(oldNamespaceFd, { bigint: true }).ino);
    assert.equal(oldNamespaceIno, oldScope.descriptor.observer_pid_namespace.ino);
    assert.equal(await ensureChildExit(), true);
    oldClosed = await observeOldClosure();
    assert.equal(oldClosed, true, 'Old immutable command scope did not physically close');
    fs.writeFileSync(path.join(system, 'tools/sync-tracked.js'), 'console.log(JSON.stringify({status:"ok"}));\n');
    nextPromise = flow.mainAsync(['doctor', '--exclusive', '--json'], {
      budgets: policy, signal: abort.signal, env: contextEnv(context),
      onNativeReady(descriptor) {
        nextNamespaceFd = fs.openSync('/proc/' + descriptor.worker.proc_pid + '/ns/pid', fs.constants.O_RDONLY);
        nextNamespaceIno = String(fs.fstatSync(nextNamespaceFd, { bigint: true }).ino);
        assert.notEqual(nextNamespaceIno, oldNamespaceIno);
        assert(oldScope.observer_lineage.every(frame => frame.namespace.ino !== nextNamespaceIno),
          'New operation unexpectedly belongs to the old observer lineage');
      }
    });
    const result = await nextPromise, next = result.value;
    nextClosed = result.cleanup?.status === 'completed' && next.command_cleanup?.status === 'completed';
    assert.equal(next.overall_status, 'ok', JSON.stringify({ next, output }));
    assert.equal(next.team_release.status, 'released');
    assert.equal(next.command_cleanup.status, 'completed');
    assert.equal(next.ownership.cleanup.status, 'completed');
    assert.equal(nextClosed, true);
    assert.equal(String(fs.fstatSync(oldNamespaceFd, { bigint: true }).ino), oldNamespaceIno);
    t.diagnostic(JSON.stringify({ actual_cli_exit: true, old_native_scope_closed: oldClosed,
      old_namespace_fd_held_through_recovery: true, old_namespace_ino: oldNamespaceIno, next_namespace_ino: nextNamespaceIno,
      next_namespace_outside_original_lineage: true, relay_required_by_fixed_provider: true,
      next_team_release: next.team_release.status, next_command_cleanup: next.command_cleanup.status,
      next_outer_cleanup: next.ownership.cleanup.status }));
  });
