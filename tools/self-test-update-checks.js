#!/usr/bin/env node
'use strict';

const assert = require('assert');
const checkUpdates = require('./check-updates');

function asset(name) {
  return { name, browser_download_url: `https://example.invalid/${name}`, size: 1, content_type: 'application/zip' };
}

function main() {
  const latest = {
    tag_name: 'v3.2.4',
    assets: [
      asset('default.knowledge.zip'),
      asset('knowledge-v3.1.8.zip'),
      asset('Source code (zip)'),
      asset('knowledge-v3.2.4.zip')
    ]
  };
  const selected = checkUpdates.selectReleaseAsset(latest);
  assert(selected, 'selector should find the exact latest release asset');
  assert.strictEqual(selected.name, 'knowledge-v3.2.4.zip', 'selector must choose exact knowledge-v<tag>.zip');

  const missing = checkUpdates.selectReleaseAsset({
    tag_name: 'v3.2.4',
    assets: [asset('default.knowledge.zip'), asset('knowledge.zip'), asset('knowledge-v3.2.2.zip')]
  });
  assert.strictEqual(missing, null, 'selector must not fall back to generic or old zip assets');

  const tagless = checkUpdates.selectReleaseAsset({ assets: [asset('knowledge-v3.2.4.zip')] });
  assert.strictEqual(tagless, null, 'selector must not guess an asset without a release tag');

  console.log(JSON.stringify({
    schema_version: '3.2.4',
    status: 'pass',
    checks: [
      'exact latest asset selected',
      'generic zip fallback rejected',
      'tagless release rejected'
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
