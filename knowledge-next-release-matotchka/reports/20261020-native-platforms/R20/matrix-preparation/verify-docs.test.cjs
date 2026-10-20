'use strict';
const fs = require('node:fs');
const path = require('node:path');
const assert = require('node:assert/strict');
const test = require('node:test');

test('frozen package identity and public entry documentation are internally consistent', () => {
  const pkg = JSON.parse(fs.readFileSync('.knowledge/package.json', 'utf8'));
  const install = JSON.parse(fs.readFileSync('.knowledge/install-manifest.json', 'utf8'));
  const release = pkg.knowledge_release || {};
  assert.equal(typeof pkg.version, 'string');
  assert.equal(install.schema_version, pkg.version);
  assert.match(fs.readFileSync('.knowledge/config.yaml', 'utf8'), new RegExp('^version: ' + pkg.version.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '\\r?\\n'));
  assert.equal(typeof release.audit_revision, 'string');
  assert.equal(typeof release.candidate_name, 'string');
  const docs = ['README.md', 'Quick-Start.md', 'INSTALL.md', 'RELEASE_NOTES.md'];
  for (const rel of docs) {
    const file = path.join('.knowledge', rel);
    const body = fs.readFileSync(file, 'utf8');
    assert(body.includes(release.audit_revision), `${rel} does not identify the frozen revision`);
    for (const [, href] of body.matchAll(/\]\(([^)]+)\)/g)) {
      if (/^(https?:|mailto:|#|codex:)/.test(href)) continue;
      const target = decodeURIComponent(href.split('#', 1)[0]);
      if (target) assert.ok(fs.existsSync(path.resolve(path.dirname(file), target)), `${rel} -> ${href}`);
    }
  }
});
