#!/usr/bin/env node
'use strict';
// Portable Team protocol regressions. Store/main/runFlow/log writes are real;
// command steps and explicit FS faults are synthetic. No native execution.
const assert = require('assert/strict');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const os = require('os');
const { removeTempDirStrict } = require('./lib/strict-temp-cleanup');
const source = path.resolve(__dirname, '..');
const digest = data => crypto.createHash('sha256').update(data).digest('hex');
const store = require(path.join(source, 'tools/lib/team-store'));
const flow = require(path.join(source, 'tools/flow'));
const output = fs.mkdtempSync(path.join(os.tmpdir(), 'knowledge-team-protocol-'));
const cases = [];
let serial = 0;
function seed(name) {
  const targetRoot = path.join(output, 'fixtures', name);
  fs.mkdirSync(path.join(targetRoot, '.knowledge'), { recursive: true });
  fs.writeFileSync(path.join(targetRoot, '.knowledge/config.yaml'), 'updates:\n  enabled: false\n');
  const context = { mode: 'team', teamRoot: path.join(targetRoot, 'team'), repoId: 'repo', workspaceId: 'workspace',
    targetRoot, projectKnowledgeRoot: path.join(targetRoot, '.knowledge'), systemRoot: source,
    agentId: 'fresh-team-audit', git: {}, branch: 'fixture', headSha: 'a'.repeat(40), warnings: [] };
  context.stateRoot = store.workspaceStateDir(context.teamRoot, context.repoId, context.workspaceId);
  store.registerWorkspace(context);
  return { context, steps: 0, targetRoot };
}
function result(f, context = f.context, name = 'doctor', success = true) {
  return flow.runFlow({ name, context, json: true }, {
    stepsForFlow: () => ['synthetic-data-only-step.js'],
    runOne: () => {
      f.steps++;
      return { step: 'synthetic', command: 'synthetic-data-only-step.js', success, exit: success ? 0 : 2,
        status: success ? 'pass' : 'fail', duration_ms: 1, semantic_errors: [], parsed: { status: success ? 'pass' : 'fail' } };
    }
  });
}
function bound(f, start) { return { ...f.context, teamRunId: start.run_id }; }
function records(f, id, kind) { return path.join(store.workspaceDir(f.context.teamRoot, 'repo', 'workspace'), 'flow-runs', id + '.' + kind + '.json'); }
function status(f, id) { return store.readTeamFlowStatus(f.context.teamRoot, 'repo', 'workspace', id); }
function rewrite(file, change) {
  const value = JSON.parse(fs.readFileSync(file)); delete value.content_sha256; change(value);
  fs.writeFileSync(file, JSON.stringify({ ...value, content_sha256: digest(JSON.stringify(value)) }, null, 2) + '\n');
}
function failed(f) {
  const start = store.beginTeamFlow(f.context, 'doctor');
  const out = result(f, bound(f, start));
  store.finalizeTeamFlow(f.context, start, { ...out, overall_status: 'failed', failure_code: 'release_fault' }, { status: 'failed', code: 'release_fault', physical_release_status: 'released' });
  return start;
}
async function main(f, changes = {}) {
  const logs = [], errors = [], log = console.log, err = console.error, priorExit = process.exitCode;
  let out, error;
  console.log = (...v) => logs.push(v.join(' ')); console.error = (...v) => errors.push(v.join(' '));
  try { out = await flow.__test.main(['doctor', '--json', ...(changes.exclusive ? ['--exclusive'] : [])], {
    resolveContext: () => f.context,
    runFlow: options => result(f, options.context), ...changes.hooks
  }); } catch (caught) { error = caught; }
  finally { console.log = log; console.error = err; process.exitCode = priorExit; }
  return { out, error, logs, errors };
}
function serialError(error) {
  if (!error) return null;
  return { name: error.name, code: error.code, message: error.message, ...Object.fromEntries(Object.entries(error)) };
}
async function check(id, fn) {
  const f = seed(String(++serial).padStart(2, '0') + '-' + id.replace(/[^A-Za-z0-9_-]/g, '_')), observation = {};
  try { await fn(f, observation); cases.push({ id, status: 'pass', steps: f.steps, observation }); }
  catch (error) { cases.push({ id, status: 'fail', steps: f.steps, observation, error: serialError(error) }); }
}
function fault(code) { return Object.assign(new Error('Explicit probe fault ' + code), { code }); }
function teamSnapshot(file) {
  const stat = fs.lstatSync(file, { bigint: true });
  const result = { dev: String(stat.dev), ino: String(stat.ino), mode: String(stat.mode), mtime_ns: String(stat.mtimeNs), ctime_ns: String(stat.ctimeNs) };
  if (stat.isFile()) return { ...result, sha256: digest(fs.readFileSync(file)) };
  assert(stat.isDirectory() && !stat.isSymbolicLink());
  return { ...result, children: Object.fromEntries(fs.readdirSync(file).sort().map(name => [name, teamSnapshot(path.join(file, name))])) };
}
function assertInvalid(f, id) {
  const read = status(f, id); assert.equal(read.finalization_status, 'invalid'); assert.equal(read.last_status, 'unknown');
}
(async () => {
 try {
  await check('canonical_state_success', async (f, o) => { const r = await main(f); o.result = r.out; assert.ifError(r.error); assert.equal(r.out.overall_status, 'ok'); assert.equal(status(f, r.out.run_id).last_status, 'ok'); });
  await check('selected_internal_state_success', async (f, o) => {
    f.context.stateRoot = path.join(f.context.teamRoot, 'selected-state');
    const r = await main(f); o.result = r.out; o.error = serialError(r.error);
    assert.ifError(r.error); assert.equal(r.out.overall_status, 'ok');
    const reopened = status(f, r.out.run_id); o.reopened = reopened;
    assert.equal(reopened.last_status, 'ok'); assert.equal(reopened.stateRoot, f.context.stateRoot);
    assert.equal(store.listTeamStatus(f.context.teamRoot).repos[0].workspaces[0].stateRoot, f.context.stateRoot);
  });
  for (const kind of ['outside', 'team_root']) await check(kind + '_state_refused_before_step', async (f, o) => {
    f.context.stateRoot = kind === 'outside' ? path.join(f.targetRoot, 'outside-state') : f.context.teamRoot;
    const before = teamSnapshot(f.context.teamRoot);
    const r = await main(f, { exclusive: true }); o.result = r.out; o.error = serialError(r.error); o.steps = f.steps;
    assert(r.error || r.out?.overall_status === 'failed'); assert.equal(f.steps, 0);
    assert.equal(fs.existsSync(path.join(f.context.stateRoot, 'maintenance')), false);
    assert.deepEqual(teamSnapshot(f.context.teamRoot), before, 'Admission changed the registry, lock layout or attempts before refusing the state root');
  });
  await check('present_null_final_invalid', (f, o) => { const start = store.beginTeamFlow(f.context, 'doctor'); fs.writeFileSync(records(f, start.run_id, 'final'), 'null'); o.read = status(f, start.run_id); assertInvalid(f, start.run_id); });
  await check('orphan_final_invalid', (f, o) => { const start = failed(f); fs.unlinkSync(records(f, start.run_id, 'start')); o.read = status(f, start.run_id); assertInvalid(f, start.run_id); });
  await check('real_missing_final_incomplete', (f, o) => { const start = store.beginTeamFlow(f.context, 'doctor'); o.read = status(f, start.run_id); assert.equal(o.read.finalization_status, 'incomplete'); });
  for (const field of ['release', 'finished_at', 'checks_status']) await check('failed_without_' + field + '_invalid', (f, o) => {
    const start = failed(f); rewrite(records(f, start.run_id, 'final'), value => { delete value[field]; });
    o.read = status(f, start.run_id); assertInvalid(f, start.run_id);
    assert.throws(() => store.beginTeamFlow(f.context, 'doctor', start.run_id), { code: 'team_flow_retry_requires_reconciliation' });
  });
  await check('different_flow_log_refused', (f, o) => {
    const start = store.beginTeamFlow(f.context, 'doctor'), out = result(f, bound(f, start), 'scan');
    let error; try { o.final = store.finalizeTeamFlow(f.context, start, out, { status: 'not_requested' }); } catch (e) { error = e; }
    o.error = serialError(error); assert(error, 'Producer accepted scan log as Doctor result');
  });
  await check('different_agent_context_log_refused', (f, o) => {
    const start = store.beginTeamFlow(f.context, 'doctor'), out = result(f, { ...bound(f, start), agentId: 'different-agent' });
    let error; try { o.final = store.finalizeTeamFlow(f.context, start, out, { status: 'not_requested' }); } catch (e) { error = e; }
    o.error = serialError(error); assert(error, 'Producer accepted another context log');
  });
  await check('mutated_caller_start_cannot_poison_final', (f, o) => {
    const start = store.beginTeamFlow(f.context, 'doctor'), out = result(f, bound(f, start));
    start.flow = 'scan'; start.retry_of = 'TFR-' + 'f'.repeat(32);
    let error; try { o.final = store.finalizeTeamFlow(f.context, start, out, { status: 'not_requested' }); } catch (e) { error = e; }
    o.error = serialError(error);
    assert(error || (o.final.flow === 'doctor' && o.final.retry_of === null), 'Caller object poisoned immutable final record');
  });
  await check('result_counters_match_log', (f, o) => {
    const start = store.beginTeamFlow(f.context, 'doctor'), out = result(f, bound(f, start)); out.steps_total += 1;
    let error; try { o.final = store.finalizeTeamFlow(f.context, start, out, { status: 'not_requested' }); } catch (e) { error = e; }
    o.error = serialError(error); assert(error, 'Producer accepted mismatched result/log counters');
  });
  await check('primary_error_retains_run_id', async (f, o) => {
    const r = await main(f, { hooks: { runFlow: () => { throw fault('primary_fault'); } } }); o.error = serialError(r.error);
    assert.equal(r.error?.code, 'primary_fault'); assert.match(r.error.run_id || '', /^TFR-[a-f0-9]{32}$/);
    assert.equal(status(f, r.error.run_id).last_status, 'failed');
  });
  await check('final_write_failure_retains_run_id', async (f, o) => {
    const write = fs.writeFileSync;
    fs.writeFileSync = function(file, ...args) { if (String(file).endsWith('.final.json')) throw fault('EIO'); return write.call(this, file, ...args); };
    let r; try { r = await main(f); } finally { fs.writeFileSync = write; }
    o.result = r.out; assert.equal(r.out.overall_status, 'failed'); assert.match(r.out.run_id || '', /^TFR-/);
    assert.equal(status(f, r.out.run_id).finalization_status, 'incomplete');
  });
  await check('release_then_final_failure_preserves_both', async (f, o) => {
    const append = fs.appendFileSync, write = fs.writeFileSync;
    fs.appendFileSync = function(file, data, ...args) { if (String(data).includes('lock_released')) throw fault('EIO'); return append.call(this, file, data, ...args); };
    fs.writeFileSync = function(file, ...args) { if (String(file).endsWith('.final.json')) throw fault('ENOSPC'); return write.call(this, file, ...args); };
    let r; try { r = await main(f, { exclusive: true }); } finally { fs.appendFileSync = append; fs.writeFileSync = write; }
    o.result = r.out; assert.equal(r.out.overall_status, 'failed'); assert.equal(r.out.lock_release_error, 'EIO');
    assert.equal(r.out.team_release.physical_release_status, 'released'); assert.equal(r.out.finalization_error.code, 'ENOSPC');
    assert.match(r.out.run_id || '', /^TFR-/); assert.equal(store.teamLockStatus(f.context).status, 'safe');
  });
  await check('primary_and_secondary_error_retained_in_cli_contract', async (f, o) => {
    const write = fs.writeFileSync;
    fs.writeFileSync = function(file, ...args) { if (String(file).endsWith('.final.json')) throw fault('EIO'); return write.call(this, file, ...args); };
    let r; try { r = await main(f, { hooks: { runFlow: () => { throw fault('primary_fault'); } } }); } finally { fs.writeFileSync = write; }
    o.error = serialError(r.error); assert.equal(r.error.code, 'primary_fault'); assert.equal(r.error.finalization_error, 'EIO');
    assert.match(r.error.run_id || '', /^TFR-/);
    assert.equal(typeof flow.__test.formatCliError, 'function');
    o.cli = flow.__test.formatCliError('doctor', r.error); assert.equal(o.cli.run_id, r.error.run_id); assert.equal(o.cli.error.finalization_error, 'EIO');
  });
  for (const kind of ['start', 'final']) await check(kind + '_readback_failure_preserves_persisted_id', async (f, o) => {
    const open = fs.openSync; let faults = 0;
    fs.openSync = function(file, flags, ...args) {
      if (String(file).endsWith('.' + kind + '.json') && typeof flags === 'number' && fs.existsSync(file) && faults++ === 0) throw fault('EIO');
      return open.call(this, file, flags, ...args);
    };
    let r; try { r = await main(f); } finally { fs.openSync = open; }
    o.result = r.out; o.error = serialError(r.error); o.faults = faults;
    const id = r.out?.run_id || r.error?.run_id; assert.match(id || '', /^TFR-/);
    const marker = r.out?.finalization_error?.record_write_status || r.error?.record_write_status;
    assert.equal(marker, 'write_completed_readback_failed');
    o.reopened = status(f, id);
    if (kind === 'final') { assert.equal(r.out.overall_status, 'failed'); assert.equal(o.reopened.last_status, 'ok'); }
    else { assert.equal(f.steps, 0); assert.equal(o.reopened.finalization_status, 'incomplete'); }
  });
  await check('legacy_workspace_does_not_claim_terminal_success', f => {
    const observed = store.listTeamStatus(f.context.teamRoot).repos[0].workspaces[0];
    assert.equal(observed.last_status, 'unknown'); assert.equal(observed.finalization_status, 'legacy_unattested');
  });
  await check('incomplete_attempt_cannot_authorize_retry', f => {
    const start = store.beginTeamFlow(f.context, 'doctor');
    assert.throws(() => store.beginTeamFlow(f.context, 'doctor', start.run_id), { code: 'team_flow_retry_requires_reconciliation' });
  });
  await check('checks_ok_release_failure_remains_failed', f => {
    const start = failed(f), reopened = status(f, start.run_id);
    assert.equal(reopened.last_status, 'failed'); assert.equal(reopened.finalization.checks_status, 'ok');
    assert.equal(reopened.finalization.release.physical_release_status, 'released');
  });
  await check('explicit_failed_retry_has_distinct_id_and_successful_terminal_binding', f => {
    const prior = failed(f), retry = store.beginTeamFlow(f.context, 'doctor', prior.run_id);
    assert.notEqual(retry.run_id, prior.run_id); assert.equal(retry.retry_of, prior.run_id);
    store.finalizeTeamFlow(f.context, retry, result(f, bound(f, retry)), { status: 'released' });
    assert.equal(status(f, retry.run_id).last_status, 'ok'); assert.equal(status(f, retry.run_id).binding_version, 'run_bound_v2');
    assert.throws(() => store.beginTeamFlow(f.context, 'doctor', retry.run_id), { code: 'team_flow_retry_requires_reconciliation' });
  });
  await check('finalizing_same_attempt_twice_preserves_final_bytes', f => {
    const start = store.beginTeamFlow(f.context, 'doctor'), out = result(f, bound(f, start));
    store.finalizeTeamFlow(f.context, start, out, { status: 'not_requested' });
    const file = records(f, start.run_id, 'final'), before = fs.readFileSync(file);
    assert.throws(() => store.finalizeTeamFlow(f.context, start, out, { status: 'not_requested' }), { code: 'EEXIST' });
    assert.deepEqual(fs.readFileSync(file), before);
  });
  await check('log_byte_drift_removes_terminal_success', f => {
    const start = store.beginTeamFlow(f.context, 'doctor'), out = result(f, bound(f, start));
    store.finalizeTeamFlow(f.context, start, out, { status: 'not_requested' });
    fs.appendFileSync(path.resolve(f.context.targetRoot, out.flow_log), ' ');
    assertInvalid(f, start.run_id);
  });
  for (const edit of ['wrong_schema', 'wrong_start_hash', 'unknown_status']) await check('rehash_does_not_authorize_' + edit, f => {
    const start = failed(f);
    rewrite(records(f, start.run_id, 'final'), value => {
      if (edit === 'wrong_schema') value.schema_version = 'wrong';
      if (edit === 'wrong_start_hash') value.start_sha256 = '0'.repeat(64);
      if (edit === 'unknown_status') value.final_status = 'unknown';
    });
    assertInvalid(f, start.run_id);
    assert.throws(() => store.beginTeamFlow(f.context, 'doctor', start.run_id), { code: 'team_flow_retry_requires_reconciliation' });
  });
  await check('older_final_does_not_replace_newer_workspace_attempt', f => {
    const older = store.beginTeamFlow(f.context, 'doctor'), newer = store.beginTeamFlow(f.context, 'scan');
    store.finalizeTeamFlow(f.context, older, result(f, bound(f, older)), { status: 'not_requested' });
    const workspace = store.listTeamStatus(f.context.teamRoot).repos[0].workspaces[0];
    assert.equal(workspace.last_run_id, newer.run_id); assert.equal(workspace.last_flow, 'scan');
    assert.equal(workspace.last_status, 'incomplete');
  });
  await check('physical_release_precedes_event_failure_and_remains_observable', f => {
    const release = store.acquireTeamLock(f.context, 'flow'), append = fs.appendFileSync;
    fs.appendFileSync = function(file, data, ...args) { if (String(data).includes('lock_released')) throw fault('EIO'); return append.call(this, file, data, ...args); };
    try { assert.throws(release, error => error.code === 'EIO' && error.physical_release_status === 'released'); }
    finally { fs.appendFileSync = append; }
    assert.equal(store.teamLockStatus(f.context).status, 'safe');
  });
  await check('terminal_main_and_persisted_release_failure_agree', async f => {
    const append = fs.appendFileSync;
    fs.appendFileSync = function(file, data, ...args) { if (String(data).includes('lock_released')) throw fault('EIO'); return append.call(this, file, data, ...args); };
    let r; try { r = await main(f, { exclusive: true }); } finally { fs.appendFileSync = append; }
    assert.ifError(r.error); assert.equal(r.logs.length, 1); assert.equal(r.out.overall_status, 'failed');
    assert.equal(status(f, r.out.run_id).last_status, 'failed');
    assert.equal(r.out.lock_release_error, 'EIO'); assert.equal(r.out.team_release.physical_release_status, 'released');
  });
  await check('write_failure_hook_returns_incomplete_without_success', async f => {
    const r = await main(f, { hooks: { finalizeTeamFlow: () => { throw fault('EIO'); } } });
    assert.equal(r.out.overall_status, 'failed'); assert.equal(status(f, r.out.run_id).finalization_status, 'incomplete');
  });
  for (const kind of ['start', 'final']) for (const value of [null, [], false, 1, 'record']) await check(kind + '_physical_' + JSON.stringify(value) + '_is_invalid', f => {
    const start = store.beginTeamFlow(f.context, 'doctor');
    fs.writeFileSync(records(f, start.run_id, kind), JSON.stringify(value));
    assertInvalid(f, start.run_id);
  });
  await check('referenced_but_absent_attempt_is_unknown_invalid', f => assertInvalid(f, 'TFR-' + 'e'.repeat(32)));
  await check('state_root_existing_file_is_refused_without_step', async f => {
    f.context.stateRoot = path.join(f.context.teamRoot, 'selected-file'); fs.writeFileSync(f.context.stateRoot, 'sentinel');
    const r = await main(f); assert(r.error); assert.equal(f.steps, 0); assert.equal(fs.readFileSync(f.context.stateRoot, 'utf8'), 'sentinel');
  });
  await check('log_parent_existing_file_is_refused_before_start', async f => {
    const logs = path.join(f.context.stateRoot, 'maintenance/flow-logs'); fs.writeFileSync(logs, 'sentinel');
    const before = fs.readFileSync(store.findWorkspace(f.context.teamRoot, 'workspace', 'repo').path);
    const r = await main(f); assert(r.error); assert.equal(f.steps, 0);
    assert.deepEqual(fs.readFileSync(store.findWorkspace(f.context.teamRoot, 'workspace', 'repo').path), before);
  });
  await check('start_write_failure_never_creates_pointer_or_executes_steps', async f => {
    const file = store.findWorkspace(f.context.teamRoot, 'workspace', 'repo').path, before = fs.readFileSync(file), write = fs.writeFileSync;
    fs.writeFileSync = function(target, ...args) { if (String(target).endsWith('.start.json')) throw fault('ENOSPC'); return write.call(this, target, ...args); };
    let r; try { r = await main(f); } finally { fs.writeFileSync = write; }
    assert.equal(r.error?.code, 'ENOSPC'); assert.equal(r.error.record_write_status, undefined);
    assert.equal(f.steps, 0); assert.deepEqual(fs.readFileSync(file), before);
  });
  await check('write_completed_final_readback_failure_does_not_authorize_repeat', async f => {
    const open = fs.openSync; let injected = false;
    fs.openSync = function(file, flags, ...args) {
      if (!injected && String(file).endsWith('.final.json') && typeof flags === 'number') { injected = true; throw fault('EIO'); }
      return open.call(this, file, flags, ...args);
    };
    let r; try { r = await main(f); } finally { fs.openSync = open; }
    assert.equal(r.out.finalization_error.record_write_status, 'write_completed_readback_failed');
    assert.equal(status(f, r.out.run_id).last_status, 'ok');
    assert.throws(() => store.beginTeamFlow(f.context, 'doctor', r.out.run_id), { code: 'team_flow_retry_requires_reconciliation' });
  });
  for (const legacyStatus of ['ok', 'failed']) await check('valid_completed_v1_' + legacyStatus + '_keeps_explicit_legacy_contract', f => {
    const start = store.beginTeamFlow(f.context, 'doctor'), out = result(f, bound(f, start));
    store.finalizeTeamFlow(f.context, start, { ...out, overall_status: legacyStatus }, { status: 'not_requested' });
    // Deliberate legacy-format fixture; not historical runtime execution.
    rewrite(records(f, start.run_id, 'start'), value => {
      value.schema_version = 'knowledge-team-flow-start.v1'; delete value.state_root; delete value.target_root; delete value.project_knowledge_root;
    });
    const saved = JSON.parse(fs.readFileSync(records(f, start.run_id, 'start')));
    rewrite(records(f, start.run_id, 'final'), value => { value.schema_version = 'knowledge-team-flow-finalization.v1'; value.start_sha256 = saved.content_sha256; delete value.state_root; });
    const before = fs.readFileSync(records(f, start.run_id, 'final'));
    const reopened = status(f, start.run_id);
    assert.equal(reopened.last_status, legacyStatus); assert.equal(reopened.binding_version, 'legacy_v1');
    assert.deepEqual(fs.readFileSync(records(f, start.run_id, 'final')), before);
    if (legacyStatus === 'failed') {
      const retry = store.beginTeamFlow(f.context, 'doctor', start.run_id);
      assert.equal(retry.schema_version, 'knowledge-team-flow-start.v2'); assert.equal(retry.retry_of, start.run_id);
    }
  });
  await check('unfinished_v1_cannot_be_finalized_under_v2_authority', f => {
    const start = store.beginTeamFlow(f.context, 'doctor');
    rewrite(records(f, start.run_id, 'start'), value => { value.schema_version = 'knowledge-team-flow-start.v1'; delete value.state_root; delete value.target_root; delete value.project_knowledge_root; });
    const saved = JSON.parse(fs.readFileSync(records(f, start.run_id, 'start')));
    assert.throws(() => store.finalizeTeamFlow(f.context, saved, result(f, bound(f, saved)), { status: 'not_requested' }), { code: 'team_flow_retry_requires_reconciliation' });
    assert.equal(status(f, saved.run_id).finalization_status, 'incomplete');
  });
  await check('same_workspace_id_in_two_repositories_needs_explicit_repo', f => {
    const other = { ...f.context, repoId: 'other-repo', agentId: 'other-agent' };
    other.stateRoot = store.workspaceStateDir(other.teamRoot, other.repoId, other.workspaceId);
    store.registerWorkspace(other);
    assert.throws(() => store.findWorkspace(other.teamRoot, other.workspaceId), { code: 'workspace_id_ambiguous' });
    const otherFile = store.findWorkspace(other.teamRoot, other.workspaceId, other.repoId).path, before = fs.readFileSync(otherFile);
    store.unregisterWorkspace(f.context.teamRoot, f.context.workspaceId, f.context.repoId);
    assert.deepEqual(fs.readFileSync(otherFile), before);
    assert.equal(store.findWorkspace(f.context.teamRoot, f.context.workspaceId, f.context.repoId).workspace.status, 'archived');
  });
  await check('flow_log_validation_rejects_changed_attempt_id', f => {
    const start = store.beginTeamFlow(f.context, 'doctor'), out = result(f, bound(f, start));
    const file = path.resolve(f.context.targetRoot, out.flow_log), log = JSON.parse(fs.readFileSync(file));
    assert.deepEqual(flow.__test.validateFlowLogReadback(log, log), []);
    assert(flow.__test.validateFlowLogReadback(log, { ...log, team_run_id: 'TFR-' + 'd'.repeat(32) }).includes('team_run_id mismatch'));
  });
  const passed = cases.filter(item => item.status === 'pass').length;
  process.stdout.write(JSON.stringify({ status: passed === cases.length ? 'pass' : 'fail',
    checks_total: cases.length, checks_passed: passed, checks: cases,
    evidence_kind: 'real Team store/main/runFlow/log integration with synthetic command steps and scoped FS faults',
    native_execution: false, real_cli_children: false }, null, 2) + '\n');
  process.exitCode = passed === cases.length ? 0 : 1;
 } finally { removeTempDirStrict(output); }
})().catch(error => { process.stderr.write(error.stack + '\n'); process.exitCode = 1; });
