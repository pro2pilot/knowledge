'use strict';
const assert = require('assert/strict');
const fs = require('fs');
const path = require('path');
const { EventEmitter } = require('events');
const source = path.resolve(process.argv[2]);
const root = path.resolve(process.argv[3]);
fs.mkdirSync(root);
const flow = require(path.join(source, 'tools/flow.js'));
const checks = [];
const fault = code => Object.assign(new Error(code), { code });
const context = name => {
  const targetRoot = path.join(root, name), kb = path.join(targetRoot, '.knowledge');
  fs.mkdirSync(kb, { recursive: true });
  return { mode: 'repo', systemRoot: source, targetRoot, projectKnowledgeRoot: kb, stateRoot: kb,
    teamRoot: null, repoId: 'test', agentId: 'test', warnings: [], workspaceId: null };
};
const step = success => ({ step: 'fixture', command: 'fixture.js', success, exit: success ? 0 : 2,
  status: success ? 'pass' : 'fail', duration_ms: 1, semantic_errors: [], parsed: { status: success ? 'pass' : 'fail' } });
async function check(name, fn) {
  try { await fn(context(String(checks.length))); checks.push({ name, status: 'pass' }); }
  catch (e) { checks.push({ name, status: 'fail', error: e.stack }); }
}
async function execute(ctx, { stepPass = true, thrown = false, releaseFail = false, args = [], logFail = false } = {}) {
  const logs = [], errors = [], order = [];
  const log = console.log, err = console.error, exit = process.exitCode;
  let out, caught;
  console.log = (...v) => logs.push(v.join(' ')); console.error = (...v) => errors.push(v.join(' '));
  try {
    out = await flow.__test.main(['import', '--exclusive', ...args], {
      resolveContext: () => ({ ...ctx, mode: 'team' }),
      // This group tests CLI ordering/error preservation with isolated hooks.
      // Physical team persistence/reopen/retry is covered by team-finalization.
      beginTeamFlow: () => null,
      acquireTeamLock: () => () => { order.push('release'); if (releaseFail) throw fault('release_fault'); return { status: 'released' }; },
      runFlow: options => {
        if (thrown) throw fault('primary_fault');
        return flow.runFlow({ ...options, context: ctx }, {
          stepsForFlow: () => ['fixture.js'], runOne: () => step(stepPass),
          ...(logFail ? { writeFlowLog: () => { throw fault('log_fault'); } } : {})
        });
      },
      launchInspector: async () => { order.push('launch'); return { status: 'started' }; }
    });
  } catch (e) { caught = e; }
  finally { console.log = log; console.error = err; }
  const exitCode = process.exitCode; process.exitCode = exit;
  return { out, caught, logs, errors, order, exitCode };
}
(async () => {
  await check('success launches only after release', async ctx => {
    const r = await execute(ctx); assert.deepEqual(r.order, ['release', 'launch']);
    assert.equal(r.out.status, 'ok'); assert.equal(r.out.finalization_status, 'completed');
    assert(!r.logs.join('\n').includes('Inspector opened'));
  });
  for (const args of [['--json'], ['--quiet']]) await check(`${args[0]} suppresses launch`, async ctx => {
    const r = await execute(ctx, { args }); assert.deepEqual(r.order, ['release']);
    if (args[0] === '--json') assert.equal(JSON.parse(r.logs.join('\n')).status, 'ok');
  });
  for (const stepPass of [true, false]) await check(`release failure retains evidence (checks=${stepPass})`, async ctx => {
    const r = await execute(ctx, { stepPass, releaseFail: true, args: ['--json'] });
    assert.equal(r.caught, undefined); assert.equal(r.exitCode, 2); assert.deepEqual(r.order, ['release']);
    const out = JSON.parse(r.logs.join('\n')); assert.equal(out.status, 'failed');
    assert.equal(out.checks_status, stepPass ? 'ok' : 'failed'); assert.equal(out.steps.length, 1);
    assert.equal(out.failure_code, stepPass ? 'team_flow_release_failed' : null);
    assert.deepEqual(out.finalization_error, { stage: 'team_flow_release', code: 'release_fault' });
    assert.equal(out.onboarding_follow_up, null); assert.equal(out.flow_log_status, 'written');
    assert.equal(fs.readFileSync(path.resolve(ctx.targetRoot, out.flow_log)).length, out.flow_log_bytes);
  });
  await check('nonquiet release failure never launches or offers onboarding', async ctx => {
    const r = await execute(ctx, { releaseFail: true }); assert.deepEqual(r.order, ['release']);
    assert.equal(r.out.onboarding_follow_up, null); assert(!r.logs.join('\n').includes('First-run'));
  });
  await check('thrown primary preserved alongside release failure without stdout', async ctx => {
    const r = await execute(ctx, { thrown: true, releaseFail: true, args: ['--json'] });
    assert.equal(r.caught.code, 'primary_fault'); assert.equal(r.caught.lock_release_error, 'release_fault');
    assert.deepEqual(r.logs, []); assert.deepEqual(r.order, ['release']);
  });
  for (const releaseFail of [true, false]) await check(`failed log prevents onboarding (release failure=${releaseFail})`, async ctx => {
    const r = await execute(ctx, { logFail: true, releaseFail }); assert.deepEqual(r.order, ['release']);
    assert.equal(r.out.failure_code, 'flow_log_write_failed'); assert.equal(r.out.onboarding_follow_up, null);
  });
  await check('spawn asynchronous and synchronous errors are represented safely', async ctx => {
    fs.writeFileSync(path.join(ctx.projectKnowledgeRoot, 'inspector.js'), '// synthetic entry; never executed');
    const env = { CI: process.env.CI, KNOWLEDGE_FLOW_NO_OPEN: process.env.KNOWLEDGE_FLOW_NO_OPEN };
    delete process.env.CI; delete process.env.KNOWLEDGE_FLOW_NO_OPEN;
    try {
      const r = await flow.__test.launchInspectorForOnboarding(ctx, { spawn: () => {
        const child = new EventEmitter(); process.nextTick(() => child.emit('error', fault('EACCES'))); return child;
      }});
      assert.deepEqual(r, { attempted: true, status: 'failed', code: 'EACCES' });
      const s = await flow.__test.launchInspectorForOnboarding(ctx, { spawn: () => { throw fault('unsafe\ntext'); } });
      assert.equal(s.code, 'inspector_spawn_failed');
      process.env.CI = 'true';
      assert.equal((await flow.__test.launchInspectorForOnboarding(ctx)).status, 'disabled');
      delete process.env.CI; process.env.KNOWLEDGE_FLOW_NO_OPEN = '1';
      assert.equal((await flow.__test.launchInspectorForOnboarding(ctx)).status, 'disabled');
    } finally { for (const [k,v] of Object.entries(env)) { if (v === undefined) delete process.env[k]; else process.env[k] = v; } }
  });
  await check('missing Inspector entry is reported', async ctx => {
    assert.equal((await flow.__test.launchInspectorForOnboarding(ctx)).status, 'missing_entrypoint');
  });
  await check('team acquire preserves acquired-event error plus cleanup/event failures', async ctx => {
    const managerPath = require.resolve(path.join(source, 'tools/lib/contained-lock-manager'));
    const storePath = require.resolve(path.join(source, 'tools/lib/json-store'));
    const teamPath = require.resolve(path.join(source, 'tools/lib/team-store'));
    const manager = require(managerPath), store = require(storePath);
    const acquire = manager.acquireContainedLock, append = store.appendNdjson;
    let events = 0, released = 0;
    manager.acquireContainedLock = () => ({ lock_id: 'fixture', release: () => { released++; throw fault('cleanup_fault'); } });
    store.appendNdjson = () => { throw fault(++events === 1 ? 'acquired_event_fault' : 'timeout_event_fault'); };
    delete require.cache[teamPath];
    const teamRoot = path.join(ctx.targetRoot, 'team'); fs.mkdirSync(teamRoot);
    try {
      const team = require(teamPath);
      assert.throws(() => team.acquireTeamLock({ ...ctx, mode: 'team', teamRoot, repoId: 'test' }), e =>
        e.code === 'acquired_event_fault' && e.lock_release_error === 'cleanup_fault' && e.lock_event_error === 'timeout_event_fault');
      assert.equal(events, 2); assert.equal(released, 1);
    } finally { manager.acquireContainedLock = acquire; store.appendNdjson = append; delete require.cache[teamPath]; }
  });
  const failed = checks.filter(c => c.status !== 'pass').length;
  console.log(JSON.stringify({ status: failed ? 'fail' : 'pass', total: checks.length, passed: checks.length-failed, checks }, null, 2));
  process.exitCode = failed ? 1 : 0;
})().catch(e => { console.error(e); process.exitCode = 1; });
