'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { test } = require('node:test');
const source = path.resolve(__dirname, '..');

for (const relative of ['maintenance/knowledge_currency/index.json',
  'maintenance/knowledge_currency/receipts/prior.json', 'maintenance/recording_blockers.json']) {
  test(`fallback update policy retains mandatory evidence protection for ${relative}`, () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'knowledge-update-fallback-'));
    const state = path.join(root, '.knowledge');
    try {
      fs.mkdirSync(path.join(state, 'tools'), { recursive: true });
      fs.cpSync(path.join(source, 'tools/lib'), path.join(state, 'tools/lib'), { recursive: true });
      for (const file of ['tools/update-system-files.js', 'tools/migrate-legacy-release-gate.js', 'package.json']) {
        fs.copyFileSync(path.join(source, file), path.join(state, file));
      }
      const updater = require(path.join(state, 'tools/update-system-files'));
      const policyRoot = path.join(root, 'empty-policy');
      fs.mkdirSync(policyRoot);
      fs.writeFileSync(path.join(policyRoot, 'install-manifest.json'),
        '{"immutable_runtime_evidence_paths":[],"runtime_preserve_paths":[],"system_exclude_paths":[]}\n');
      const manifest = updater.loadInstallManifest(policyRoot);
      const backup = path.join(state, 'maintenance/install-backups/system-files-fixture');
      for (const base of [state, backup]) {
        fs.mkdirSync(path.dirname(path.join(base, relative)), { recursive: true });
        fs.writeFileSync(path.join(base, relative), '{"retained":true}\n');
      }
      assert.equal(updater.runtimePreservationProof(backup, manifest).status, 'preserved');
      fs.writeFileSync(path.join(state, relative), '{"retained":false}\n');
      const proof = updater.runtimePreservationProof(backup, manifest);
      assert.equal(proof.status, 'changed');
      assert(proof.changed_files.includes(relative));
      assert.equal(proof.hash_set_unchanged, false);
      assert.equal(fs.readFileSync(path.join(backup, relative), 'utf8'), '{"retained":true}\n');
    } finally { fs.rmSync(root, { recursive: true, force: false }); }
  });
}
