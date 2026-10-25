'use strict';
const fs = require('fs');
const path = require('path');
const [source, target, ownerFile] = process.argv.slice(2);
fs.writeFileSync(ownerFile, JSON.stringify({ pid: process.pid, proc_pid: Number(fs.readlinkSync('/proc/self')) }));
const system = path.join(target, '.knowledge');
require(path.join(source, 'tools/flow.js')).runOne('busy.js', { mode: 'repo', systemRoot: system,
  targetRoot: target, projectKnowledgeRoot: system, stateRoot: system, warnings: [] });
