'use strict';
const path = require('node:path');
const source = process.argv[2], context = JSON.parse(process.argv[3]);
const manager = require(path.join(source, 'tools/lib/contained-lock-manager.js'));
const { LOCKS } = require(path.join(source, 'tools/lib/lock-policy.js'));
const lock = manager.acquireContainedLock({ context, rootKind: 'state', rootPath: context.stateRoot,
  lockName: 'verification-control', purpose: LOCKS['verification-control'].purpose });
process.send({ type: 'held' });
setTimeout(() => { lock.release(); process.exit(0); }, 1500);
