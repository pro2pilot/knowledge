#!/usr/bin/env node
'use strict';
// knowledge-release-gate-redirect.v1: no private gate is shipped with runtime installs.
const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');
const root = path.resolve(__dirname, '..');
const canonical = path.join(root, '.knowledge', 'tools', 'release-gate.js');
if (!fs.existsSync(canonical) || fs.realpathSync(canonical) === fs.realpathSync(__filename)) {
  console.error(JSON.stringify({ status: 'blocked', reason: 'maintainer_release_gate_unavailable',
    message: 'The obsolete root gate is retired. Use the maintained release gate in the maintainer source checkout. Runtime flow release is a separate repository refresh, not release certification.' }));
  process.exitCode = 2;
} else {
  const result = spawnSync(process.execPath, [canonical, ...process.argv.slice(2)], {
    cwd: path.dirname(path.dirname(canonical)), stdio: 'inherit', windowsHide: true
  });
  if (result.error) console.error(result.error.message);
  process.exitCode = Number.isInteger(result.status) ? result.status : 1;
}
