#!/usr/bin/env node
'use strict';

const assert = require('assert').strict;
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const fixture = fs.mkdtempSync(path.join(os.tmpdir(), 'knowledge-readiness-comparison-'));
const state = path.join(fixture, '.knowledge');
fs.mkdirSync(path.join(state, 'maintenance'), { recursive: true });
Object.assign(process.env, {
  KNOWLEDGE_MODE: 'repo', KNOWLEDGE_SYSTEM_ROOT: path.resolve(__dirname, '..'),
  KNOWLEDGE_TARGET_ROOT: fixture, KNOWLEDGE_PROJECT_KNOWLEDGE_ROOT: state,
  KNOWLEDGE_STATE_ROOT: state, KNOWLEDGE_AGENT_ID: 'readiness-comparison-fixture',
  KNOWLEDGE_UPDATE_DISABLE_ON_LAUNCH: '1'
});
const { reconcile } = require('./lib/queue-lifecycle');
const { granularFinding, taskReadiness, compareTaskReadiness } = require('./lib/repair-on-touch');
const { sanitizedOpportunityProjection } = require('./repair-on-touch');
const checks = [];
function check(name, action) { action(); checks.push({ name, status: 'pass' }); }
const clone = (value) => JSON.parse(JSON.stringify(value));
const digest = (file) => crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');
const scope = { direct_modules: ['sample'], direct_artifacts: ['src/current.js'], dependency_modules: [], dependency_artifacts: [], essential_dependency_modules: [] };
const stale = { items: [] }, queue = { queue: [] };
reconcile({ staleItems: stale, repairQueue: queue, agentId: 'fixture', source: 'fixture', timestamp: '2026-01-01T00:00:00.000Z', findings: [
  ...Array.from({ length: 3 }, (_, index) => ({ module_id: 'sample', code: 'tracked_file_needs_recheck', artifact: `src/${index}.js`, score_cost: 13 })),
  ...Array.from({ length: 12 }, (_, index) => ({ module_id: 'sample', code: 'tracked_file_changed', artifact: `history/${index}.js`, score_cost: 7 })),
  { module_id: 'protected', code: 'security_finding', artifact: 'protected/auth.js', security_sensitive: true, safe_during_current_task: false }
] });
const records = stale.items;
const planned = records.filter((row) => row.artifact.startsWith('src/')).map((row) => ({ ...granularFinding(row), status: 'selected' }));
const artifact = { task_scope: scope, opportunities: planned };
const provenance = { lifecycle_ids: [], receipts: [], dedicated_receipts: [], invalid: [], status: 'verified' };
function persist(rows) {
  fs.writeFileSync(path.join(state, 'maintenance/stale_items.json'), JSON.stringify({ items: rows }));
  fs.writeFileSync(path.join(state, 'maintenance/repair_queue.json'), JSON.stringify({ queue: rows }));
}
function changeFirst(update) { return records.map((row) => row.lifecycle_id === planned[0].lifecycle_id ? { ...row, ...update } : row); }

try {
  persist(records);
  const beforeHashes = ['stale_items.json', 'repair_queue.json'].map((file) => digest(path.join(state, 'maintenance', file)));
  check('RC1 comparison reproduces 61 to 0 with unchanged cohort', () => {
    assert.equal(taskReadiness(planned, scope).score, 61);
    assert.equal(taskReadiness(records, scope).score, 0);
  });
  check('same native projection reports stable 61 to 61 and separate current debt', () => {
    const result = sanitizedOpportunityProjection(artifact, provenance);
    assert.equal(result.task_readiness_before.score, 61);
    assert.equal(result.task_readiness_after.score, 61);
    assert.equal(result.current_task_readiness.score, 0);
    assert.equal(result.task_readiness_comparison.status, 'comparable');
    assert.equal(result.task_readiness_comparison.observed_outside_cohort_lifecycle_ids.length, 13);
    assert.equal(result.current_findings.find((row) => row.security_sensitive).status, 'open');
  });
  check('projection is read only for both raw ledgers', () => {
    assert.deepEqual(['stale_items.json', 'repair_queue.json'].map((file) => digest(path.join(state, 'maintenance', file))), beforeHashes);
  });
  check('missing current cohort member has no numeric delta', () => {
    const result = compareTaskReadiness(planned, records.filter((row) => row.lifecycle_id !== planned[0].lifecycle_id), scope);
    assert.equal(result.reason, 'cohort_records_missing'); assert.equal(result.after.score, null);
  });
  check('reopened occurrence invalidates comparison', () => assert.equal(compareTaskReadiness(planned, changeFirst({ occurrence: 2 }), scope).reason, 'cohort_occurrence_changed'));
  check('same occurrence number with different observation time invalidates comparison', () => assert.equal(compareTaskReadiness(planned, changeFirst({ opened_at: '2026-01-02T00:00:00.000Z' }), scope).reason, 'cohort_occurrence_changed'));
  check('same ID with changed artifact identity invalidates comparison', () => assert.equal(compareTaskReadiness(planned, changeFirst({ artifact: 'src/other.js', affected_artifacts: ['src/other.js'] }), scope).reason, 'cohort_occurrence_changed'));
  check('invalid observation date is unavailable', () => assert.equal(compareTaskReadiness(planned, changeFirst({ opened_at: 'invalid' }), scope).reason, 'cohort_occurrence_invalid'));
  check('duplicate plan identity is unavailable', () => assert.equal(compareTaskReadiness([...planned, planned[0]], records, scope).reason, 'cohort_identity_invalid'));
  check('duplicate current identity is unavailable', () => assert.equal(compareTaskReadiness(planned, [...records, records[0]], scope).reason, 'current_lifecycle_identity_invalid'));
  check('absent current lifecycle is unavailable', () => assert.equal(compareTaskReadiness(planned, null, scope).reason, 'current_lifecycle_unavailable'));
  check('absent plan is unavailable rather than empty success', () => assert.equal(compareTaskReadiness(null, records, scope).reason, 'planned_cohort_unavailable'));
  check('empty cohort is not an invented perfect score', () => {
    const result = compareTaskReadiness([], records, scope);
    assert.equal(result.status, 'not_applicable'); assert.equal(result.before.score, null); assert.equal(result.after.score, null);
  });
  check('legacy plan without observation provenance remains readable but delta is unavailable', () => {
    const legacy = planned.map(({ occurrence, opened_at, reopened_at, ...row }) => row);
    assert.equal(compareTaskReadiness(legacy, records, scope).reason, 'cohort_occurrence_invalid');
  });
  check('frozen plan weights do not silently change between measurements', () => assert.equal(compareTaskReadiness(planned, records.map((row) => ({ ...row, score_cost: 99 })), scope).after.score, 61));
  check('raw closed status without native validated closure cannot improve cohort', () => {
    persist(records.map((row) => planned.some((item) => item.lifecycle_id === row.lifecycle_id) ? { ...row, status: 'closed' } : row));
    assert.equal(sanitizedOpportunityProjection(artifact, provenance).task_readiness_after.score, 61);
  });
  check('only supplied validated fixture closures improve cohort; protected neighbor stays open', () => {
    const result = sanitizedOpportunityProjection(artifact, { ...provenance, lifecycle_ids: planned.map((row) => row.lifecycle_id) });
    assert.equal(result.task_readiness_after.score, 100); assert(result.current_task_readiness.score < 100);
    assert.equal(result.current_findings.find((row) => row.security_sensitive).status, 'open');
  });
  check('another repository module and file identity need no project IDs', () => {
    const otherStale = { items: [] }, otherQueue = { queue: [] };
    reconcile({ staleItems: otherStale, repairQueue: otherQueue, agentId: 'other-fixture', source: 'fixture', timestamp: '2026-02-01T00:00:00.000Z', findings: [{ module_id: 'another_module', code: 'tracked_file_changed', artifact: 'lib/another.js', score_cost: 7 }] });
    const otherScope = { ...scope, direct_modules: ['another_module'], direct_artifacts: ['lib/another.js'] };
    const result = compareTaskReadiness(otherStale.items.map(granularFinding), clone(otherStale.items), otherScope);
    assert.equal(result.status, 'comparable'); assert.equal(result.before.score, 93); assert.equal(result.after.score, 93);
  });
  check('accessor inputs are unavailable without invoking caller code', () => {
    let calls = 0;
    const hostile = {};
    Object.defineProperty(hostile, 'direct_modules', { enumerable: true, get() { calls++; throw Error('caller getter'); } });
    assert.equal(taskReadiness(planned, hostile).reason, 'readiness_input_invalid');
    assert.equal(compareTaskReadiness(planned, records, hostile).reason, 'readiness_input_invalid');
    assert.equal(calls, 0);
  });
  check('proxy inputs are unavailable without invoking proxy traps', () => {
    let calls = 0;
    const hostile = new Proxy([], { get() { calls++; throw Error('caller proxy'); }, ownKeys() { calls++; throw Error('caller proxy'); } });
    assert.equal(taskReadiness(hostile, scope).reason, 'readiness_input_invalid');
    assert.equal(compareTaskReadiness(planned, hostile, scope).reason, 'readiness_input_invalid');
    assert.equal(calls, 0);
  });
  console.log(JSON.stringify({ status: 'pass', checks_total: checks.length, checks, evidence_kind: 'isolated regression; fixture provenance is not production KVE/KVR' }, null, 2));
} finally {
  const resolved = fs.realpathSync(fixture);
  const parent = fs.realpathSync(os.tmpdir());
  const relative = path.relative(parent, resolved);
  if (!relative || relative === '..' || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative)) throw new Error('Unsafe fixture cleanup target');
  fs.rmSync(resolved, { recursive: true, force: false });
}
