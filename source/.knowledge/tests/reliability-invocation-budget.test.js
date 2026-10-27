'use strict';
const test = require('node:test'), assert = require('node:assert/strict');
const fs = require('node:fs'), path = require('node:path'), os = require('node:os'), crypto = require('node:crypto');
const { spawn } = require('node:child_process');
const source = process.env.KNOWLEDGE_INVOCATION_TEST_SOURCE || path.resolve(__dirname, '..');
const control = require(path.join(source, 'tools/lib/verification-control.js'));
const recovery = require(path.join(source, 'tools/lib/verification-recovery.js'));
const runner = require(path.join(source, 'tools/lib/command-runner.js'));
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));

test('invocation recovery mutex waiting consumes the original remaining budget', { skip: process.platform !== 'linux', timeout: 45000 }, async t => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'knowledge-invocation-budget-'));
  const stateRoot = path.join(root, '.knowledge'); fs.mkdirSync(stateRoot);
  const context = { stateRoot, projectKnowledgeRoot: stateRoot, targetRoot: root, systemRoot: source };
  let session, holder, holderExited = false, closed = false, stderr = '';
  t.after(async () => {
    if (session) { try { closed = (await session.finish()).status === 'completed'; } catch {} }
    for (let n = 0; holder && !holderExited && n < 200; n++) await delay(10);
    if (holder && !holderExited) { holder.kill('SIGKILL'); for (let n = 0; !holderExited && n < 200; n++) await delay(10); }
    if (closed && (!holder || holderExited)) fs.rmSync(root, { recursive: true, force: true });
    else t.diagnostic(JSON.stringify({ fixture_retained_unconfirmed: root }));
  });
  session = await runner.createCommandSession({ budgets: { setupMs: 30000, workMs: 60000, cleanupMs: 5000, progressMs: 0 } });
  const scope = JSON.parse(JSON.stringify(session.scope));
  const invocation = { schema_version: 'knowledge-verification-invocation.v1', nonce_sha256: 'd'.repeat(64),
    scope_sha256: crypto.createHash('sha256').update(JSON.stringify(scope)).digest('hex'), scope };
  const admitted = await session.run({ executable: process.execPath,
    args: [path.join(__dirname, 'helpers/reliability-invocation-control-worker.cjs'), source, JSON.stringify({ context, invocation })], cwd: root });
  assert.equal(admitted.status, 0, admitted.stderr); assert.equal(admitted.cleanup.status, 'completed');
  const attempt = JSON.parse(admitted.stdout).attempt;
  closed = (await session.finish()).status === 'completed'; assert.equal(closed, true);
  holder = spawn(process.execPath, [path.join(__dirname, 'helpers/reliability-control-mutex-holder.cjs'), source, JSON.stringify(context)],
    { stdio: ['ignore', 'ignore', 'pipe', 'ipc'], env: { ...process.env, NODE_OPTIONS: '', NODE_PATH: '' } });
  holder.stderr.on('data', bytes => { stderr += bytes; }); holder.once('exit', () => { holderExited = true; });
  await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('Actual mutex holder did not become ready')), 10000);
    holder.once('error', error => { clearTimeout(timer); reject(error); });
    holder.once('message', value => { clearTimeout(timer); value?.type === 'held' ? resolve() : reject(new Error('Invalid mutex readiness')); });
    holder.once('exit', () => { clearTimeout(timer); reject(new Error('Mutex holder exited before readiness: ' + stderr)); });
  });
  const started = process.hrtime.bigint(); let cause;
  try { recovery.recoverAttempt(context, { attempt_id: attempt.attempt_id, generation: attempt.generation,
    deadline_ns: String(started + 200000000n) }); } catch (error) { cause = error; }
  const elapsed = Number(process.hrtime.bigint() - started) / 1e6;
  t.diagnostic(JSON.stringify({ actual_mutex_hold_ms: 1500, original_recovery_allowance_ms: 200,
    elapsed_ms: elapsed, code: cause?.code, holder_exited_when_returned: holderExited, stderr }));
  assert(cause && ['lock_timeout', 'verification_recovery_budget_exceeded'].includes(cause.code));
  assert(elapsed < 800, 'A nearly exhausted recovery cannot acquire a fresh 5000 ms mutex wait');
  const current = control.readStatus(context).attempt;
  assert.equal(current.claimed, true); assert.equal(current.revision, attempt.revision);
});
