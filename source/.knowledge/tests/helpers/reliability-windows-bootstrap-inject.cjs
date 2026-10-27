'use strict';
// Test-only launcher preload. It adds the unchanged semantic holder stall
// to the exact argv passed to native JOB_LIST creation, never replaces a
// kernel API, process birth, Job limit, signal or completion observation.
const path = require('path');
const loader = require('../../tools/lib/command-windows-native');
const load = loader.loadPreparedHelper;
let role;
process.on('message', value => { if (value?.type === 'init') role = value.role; });
loader.loadPreparedHelper = function(...args) {
  const loaded = load(...args), native = {};
  for (const name of Object.getOwnPropertyNames(loaded.native)) native[name] = loaded.native[name];
  native.bootstrapCreate = function(executable, argv, ...rest) {
    const config = JSON.parse(process.env.KNOWLEDGE_QA_HOLDER_STALL || '{}');
    process.env.KNOWLEDGE_QA_HOLDER_STALL = JSON.stringify({ ...config, bootstrap_role: role });
    return loaded.native.bootstrapCreate(executable, ['--require', path.join(__dirname, 'reliability-windows-holder-stall.cjs'), ...argv], ...rest);
  };
  return { ...loaded, native };
};
// A suspended, already-owned child boundary; the native watcher and Job
// remain real while only the launcher's JS scheduling is held.
const loadWithChildInjection = loader.loadPreparedHelper;
loader.loadPreparedHelper = function(...args) {
  const loaded = loadWithChildInjection(...args), resume = loaded.native.bootstrapResume;
  loaded.native.bootstrapResume = function(id) {
    const config = JSON.parse(process.env.KNOWLEDGE_QA_HOLDER_STALL || '{}');
    if (config.phase === 'before_resume' && config.roles?.includes(role)) {
      require('fs').writeFileSync(path.join(config.marker_directory, `${role}.before_resume.json`), JSON.stringify({phase:'before_resume',role,pid:process.pid})+'\n',{flag:'wx'});
      for (;;) Atomics.wait(new Int32Array(new SharedArrayBuffer(4)),0,0,1000);
    }
    return resume(id);
  };
  return loaded;
};
