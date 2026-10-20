'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const { fixture } = require('./helpers/currency-overlay');
const recording = require('../tools/lib/recording-blockers');
const session = 'ATW-' + 'a'.repeat(64);
const candidate = 'docs/' + ['sk', 'live', 'F'.repeat(32)].join('_') + '.md'; // Deliberately artificial privacy fixture; never a provider credential.
function setup(t) {
  const f = fixture(t, 'recording-public-data');
  f.write('.knowledge/config.json', { updates: { enabled: false } });
  f.write(candidate, 'Synthetic non-secret repository-path fixture.\n');
  return f;
}

test('recording audit: persisted raw preview, field and extension values never become public output', t => {
  const f = setup(t);
  const original = recording.registerBlocker(f.context, { field: '$.source_files[0]', value: candidate, session_id: session, language: 'ru' });
  const resolved = recording.resolveBlocker(f.context, { id: original.blocker.id, scope: 'once', reason: 'Explicit synthetic path confirmation', confirmed: true });
  assert.equal(resolved.status, 'ok');
  const file = path.join(f.state, 'maintenance/recording_blockers.json');
  const stored = JSON.parse(fs.readFileSync(file));
  const samples = ['sk-' + 'Q'.repeat(30), 'person@example.test', '/private/customer/internal.txt'];
  stored.blockers[0].preview = samples[0];
  stored.blockers[0].field = samples[0];
  stored.blockers[0].unrecognized_note = samples[1];
  stored.overrides[0].unrecognized_note = samples[2];
  fs.writeFileSync(file, JSON.stringify(stored, null, 2) + '\n');
  const before = fs.readFileSync(file);
  const result = recording.listBlockers(f.context);
  const text = JSON.stringify(result);
  for (const sample of samples) assert.equal(text.includes(sample), false);
  assert.equal(result.blockers[0].preview, '********');
  assert.equal(result.blockers[0].field, 'task_record');
  assert.equal(result.blockers[0].id, original.blocker.id);
  assert.equal(result.overrides[0].id, resolved.override_id);
  assert.equal(result.overrides[0].unrecognized_note, undefined);
  assert.deepEqual(fs.readFileSync(file), before, 'read-only masking must not rewrite historical registry data');
});

test('recording audit: a direct localized notice masks its caller-supplied preview and unsafe field', () => {
  const privateValue = 'sk-' + 'Q'.repeat(30);
  const notice = recording.notice({ kind: 'suspected_secret', field: privateValue, preview: 'person@example.test' }, 'ru');
  assert.equal(notice.includes(privateValue), false);
  assert.equal(notice.includes('person@example.test'), false);
  assert.match(notice, /\*{8}/);
  assert.match(notice, /заблокирована/);
});

test('recording audit: public projection preserves exact once/project approval and revoke semantics', t => {
  const f = setup(t);
  const row = recording.registerBlocker(f.context, { field: '$.source_files[0]', value: candidate, session_id: session, language: 'ru' });
  assert.deepEqual(row.blocker.allowed_actions, ['once', 'project']);
  const resolved = recording.resolveBlocker(f.context, { id: row.blocker.id, scope: 'once', reason: 'Known synthetic path', confirmed: true });
  assert.equal(resolved.status, 'ok');
  assert.equal(recording.approvedRepositoryPath(f.context, candidate, session), true);
  assert.equal(recording.approvedRepositoryPath(f.context, candidate, 'ATW-' + 'b'.repeat(64)), false);
  const list = recording.listBlockers(f.context);
  assert.equal(list.overrides[0].scope, 'once');
  assert.equal(list.overrides[0].reason, recording.OVERRIDE_REASON_CODE);
  assert.equal(list.overrides[0].session_id, session);
  assert.equal(recording.revokeOverride(f.context, { id: resolved.override_id, confirmed: true }).status, 'ok');
  assert.equal(recording.approvedRepositoryPath(f.context, candidate, session), false);
  assert.equal(recording.listBlockers(f.context).overrides[0].status, 'revoked');
});
