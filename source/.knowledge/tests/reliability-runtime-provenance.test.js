'use strict';
// Actual Linux verification of synthetic factual claims. This is provenance
// coverage, not application certification or a hermetic runtime attestation.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { fixture } = require('./helpers/currency-overlay');
const finalization = require('../tools/lib/verification-finalization');
const runtime = path.resolve(__dirname, '..');

function controlledFixture(t, name) {
  let clean = false, value;
  value = fixture({ after(callback) {
    t.after(() => {
      if (clean) return callback();
      t.diagnostic(JSON.stringify({ retained_unconfirmed_fixture: value?.root }));
    });
  } }, name);
  return { f: value, verified() { clean = true; } };
}

test('new physical KVE pins the declared critical invocation profile under a distinct format',
  { skip: process.platform !== 'linux', timeout: 90000 }, t => {
    const owned = controlledFixture(t, 'invocation-provenance'), f = owned.f;
    const checked = f.verify(); owned.verified();
    const ack = checked.verification_acceptances[0];
    const receipt = JSON.parse(fs.readFileSync(path.join(f.state, 'maintenance',
      'verification_finalizations', ack.receipt_id.slice(4) + '.json'), 'utf8'));
    assert.equal(ack.schema_version, 'knowledge-verification-acceptance.v4');
    assert.equal(receipt.schema_version, 'knowledge-verification-finalization.v4');
    for (const name of ['command-runner.js', 'command-sync-driver.js', 'command-worker.js',
      'verification-invocation.js', 'verification-cancel-observer.js', 'lock-publication.js']) {
      assert(receipt.implementation.some(pin => pin.path === 'tools/lib/' + name && /^[a-f0-9]{64}$/.test(pin.sha256)), name);
    }
    assert.equal(finalization.requireFinalizedExecutions(f.state, checked.execution_ids,
      checked.verification_acceptances).status, 'accepted');
  });

for (const relative of ['tools/lib/command-runner.js', 'tools/lib/verification-cancel-observer.js',
  'tools/native/lock-publication.c']) {
  test('changing ' + relative + ' invalidates every previously issued factual unit',
    { skip: process.platform !== 'linux', timeout: 90000 }, t => {
      const owned = controlledFixture(t, 'source-binding'), f = owned.f;
      // Old fixture builders did not copy native C. Keep the same source bytes
      // present in both cohorts before verification; only the authority binding
      // decides whether a later change invalidates this receipt.
      f.write('.knowledge/' + relative, fs.readFileSync(path.join(runtime, relative), 'utf8'));
      f.addUnit('second-source-binding');
      const checked = f.verify(); owned.verified();
      f.issue(checked);
      const prior = f.ledgers().map(bytes => bytes.toString('base64'));
      assert.equal(f.evaluate().valid, true);
      fs.appendFileSync(path.join(f.root, '.knowledge', relative), '\n// changed after physical verification\n');
      const observed = f.evaluate();
      assert.equal(observed.valid, false, 'A changed invocation authority must invalidate existing coverage');
      assert.deepEqual(Object.keys(observed.files), []);
      assert(observed.issues.some(issue => issue.code === 'currency_authority_changed'));
      assert.deepEqual(f.ledgers().map(bytes => bytes.toString('base64')), prior);
    });
}
