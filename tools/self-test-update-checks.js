#!/usr/bin/env node
'use strict';

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const checkUpdates = require('./check-updates');
const version = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'package.json'), 'utf8')).version || '3.2.5';

function asset(name) {
  return { name, browser_download_url: `https://example.invalid/${name}`, size: 1, content_type: 'application/zip' };
}

function main() {
  const latest = {
    tag_name: `v${version}`,
    assets: [
      asset('default.knowledge.zip'),
      asset('knowledge-v3.1.8.zip'),
      asset('Source code (zip)'),
      asset(`knowledge-v${version}.zip`)
    ]
  };
  const selected = checkUpdates.selectReleaseAsset(latest);
  assert(selected, 'selector should find the exact latest release asset');
  assert.strictEqual(selected.name, `knowledge-v${version}.zip`, 'selector must choose exact knowledge-v<tag>.zip');

  const missing = checkUpdates.selectReleaseAsset({
    tag_name: `v${version}`,
    assets: [asset('default.knowledge.zip'), asset('knowledge.zip'), asset('knowledge-v3.2.2.zip')]
  });
  assert.strictEqual(missing, null, 'selector must not fall back to generic or old zip assets');

  const tagless = checkUpdates.selectReleaseAsset({ assets: [asset(`knowledge-v${version}.zip`)] });
  assert.strictEqual(tagless, null, 'selector must not guess an asset without a release tag');
  assert.strictEqual(checkUpdates.compareVersions('3.2.4', '3.2.5'), -1, 'patch version comparison must detect newer releases');
  assert.strictEqual(checkUpdates.compareVersions('3.2.10', '3.2.5'), 1, 'patch version comparison must sort multi-digit patches');
  assert.strictEqual(checkUpdates.compareVersions('v3.2.5', '3.2.5'), 0, 'version comparison should ignore v prefix');

  console.log(JSON.stringify({
    schema_version: version,
    status: 'pass',
    checks: [
      'exact latest asset selected',
      'generic zip fallback rejected',
      'tagless release rejected',
      'semantic patch versions compare correctly'
    ]
  }, null, 2));
}

if (require.main === module) {
  try { main(); }
  catch (error) {
    console.error(error.stack || error.message);
    process.exit(1);
  }
}
