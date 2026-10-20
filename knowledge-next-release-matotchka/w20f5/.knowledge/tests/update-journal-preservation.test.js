'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { test } = require('node:test');
const source = path.resolve(__dirname, '..');
const { commitQueuePair, readQueueSnapshot } = require('../tools/lib/sync-history');
const { commitJsonTransaction } = require('../tools/lib/json-transaction');
const sha = file => crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');
const write = (file, value) => {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, typeof value === 'string' ? value : JSON.stringify(value) + '\n');
};

function fixture() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'knowledge-update-journals-'));
  const state = path.join(root, '.knowledge');
  fs.mkdirSync(path.join(state, 'tools'), { recursive: true });
  fs.cpSync(path.join(source, 'tools/lib'), path.join(state, 'tools/lib'), { recursive: true });
  for (const file of ['tools/update-system-files.js', 'tools/migrate-legacy-release-gate.js', 'package.json']) {
    fs.copyFileSync(path.join(source, file), path.join(state, file));
  }
  const stalePath = path.join(state, 'maintenance/stale_items.json');
  const repairPath = path.join(state, 'maintenance/repair_queue.json');
  write(stalePath, { items: [] });
  write(repairPath, { queue: [] });
  const priorReceipt = path.join(state, 'maintenance/verification_receipts/prior.json');
  write(priorReceipt, { retained: true });
  function append(kind = 'sync', options = {}) {
    const first = options.first || stalePath;
    const second = options.second || repairPath;
    const id = `${kind}-queue-${Date.now()}-${process.pid}-${crypto.randomBytes(12).toString('hex')}`;
    const metadata = { type: `${kind}_queue_projection`, actor: 'update-preservation-test' };
    const a = readQueueSnapshot(state, first, { items: [] });
    const b = readQueueSnapshot(state, second, { queue: [] });
    if (options.noGuards) {
      commitJsonTransaction({ stateRoot: state, transactionId: id, metadata,
        writes: [{ path: first, value: { items: [] }, containmentRoot: state },
          { path: second, value: { queue: [] }, containmentRoot: state }] });
    } else commitQueuePair({ stateRoot: state, transactionId: id, stalePath: first, repairPath: second,
      staleSnapshot: a, repairSnapshot: b, staleItems: { items: [] }, repairQueue: { queue: [] }, metadata });
    return path.join(state, 'maintenance/transactions', id);
  }
  const priorJournal = append();
  const backup = path.join(state, 'maintenance/install-backups/system-files-fixture');
  fs.mkdirSync(backup, { recursive: true });
  for (const relative of ['maintenance/transactions', 'maintenance/verification_receipts']) {
    fs.cpSync(path.join(state, relative), path.join(backup, relative), { recursive: true });
  }
  const updater = require(path.join(state, 'tools/update-system-files'));
  const proof = (allow = true) => updater.runtimePreservationProof(backup, updater.DEFAULT_MANIFEST,
    { allowQueueJournalAdditions: allow });
  return { root, state, backup, priorJournal, priorReceipt, append, proof,
    cleanup() { fs.rmSync(root, { recursive: true, force: false }); } };
}

test('post-check proof admits complete committed queue journals while preserving every prior byte', () => {
  const f = fixture();
  try {
    const before = sha(f.priorReceipt);
    f.append('sync');
    f.append('doctor');
    const strict = f.proof(false);
    assert.equal(strict.status, 'changed', 'pre-apply exact-set gate was weakened');
    const proof = f.proof();
    assert.equal(proof.status, 'preserved');
    assert.equal(proof.history_unchanged, true);
    assert.equal(proof.hash_set_unchanged, false);
    assert.equal(proof.added_files_count, 16);
    assert.equal(proof.queue_journal_additions.files.length, 16);
    assert.equal(proof.queue_journal_additions.transaction_ids.length, 2);
    assert.equal(proof.changed_files_count, 0);
    assert.equal(proof.removed_files_count, 0);
    assert.equal(sha(f.priorReceipt), before);
    for (const row of proof.queue_journal_additions.files) assert.equal(sha(path.join(f.state, row.path)), row.sha256);
  } finally { f.cleanup(); }
});

for (const mutation of ['changed-prior-journal', 'removed-prior-journal', 'added-to-prior-journal', 'changed-prior-receipt', 'new-unrelated-receipt']) {
  test(`queue append policy rejects ${mutation}`, () => {
    const f = fixture();
    try {
      f.append();
      if (mutation === 'changed-prior-journal') fs.appendFileSync(path.join(f.priorJournal, 'manifest.json'), ' ');
      if (mutation === 'removed-prior-journal') fs.unlinkSync(path.join(f.priorJournal, 'terminal.json'));
      if (mutation === 'added-to-prior-journal') write(path.join(f.priorJournal, 'extra.json'), {});
      if (mutation === 'changed-prior-receipt') fs.appendFileSync(f.priorReceipt, ' ');
      if (mutation === 'new-unrelated-receipt') write(path.join(f.state, 'maintenance/verification_receipts/new.json'), {});
      assert.equal(f.proof().status, 'changed');
    } finally { f.cleanup(); }
  });
}

for (const mutation of ['staged-corrupt', 'missing-terminal', 'extra-file', 'wrong-family', 'wrong-output', 'missing-guards']) {
  test(`queue append policy rejects new journal ${mutation}`, () => {
    const f = fixture();
    try {
      const journal = f.append(mutation === 'wrong-family' ? 'foreign' : 'sync', {
        ...(mutation === 'wrong-output' ? { first: path.join(f.state, 'settings/other.json') } : {}),
        noGuards: mutation === 'missing-guards'
      });
      if (mutation === 'staged-corrupt') fs.appendFileSync(path.join(journal, 'staged/000.new'), ' ');
      if (mutation === 'missing-terminal') fs.unlinkSync(path.join(journal, 'terminal.json'));
      if (mutation === 'extra-file') write(path.join(journal, 'unbound.json'), {});
      assert.equal(f.proof().status, 'changed');
    } finally { f.cleanup(); }
  });
}
