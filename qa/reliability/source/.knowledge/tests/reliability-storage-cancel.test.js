'use strict';
const test = require('node:test'), assert = require('node:assert/strict');
const fs = require('fs'), path = require('path'), os = require('os'), crypto = require('crypto');
const runner = require('../tools/lib/command-runner');
const { resolveKnowledgeContext } = require('../tools/lib/path-context');
const source = path.resolve(process.env.KNOWLEDGE_TEST_TARGET_SOURCE || path.join(__dirname, '..'));
const hash = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
const commands = ['sync-tracked.js', 'build-wiki-graph.js', 'lint-wiki.js', 'external-memory-status.js', 'build-routing-bundle.js',
  'build-search-index.js', 'scan-secrets.js', 'doctor.js', 'build-visual-inspector.js', 'collect-metrics.js', 'generate-pr-summary.js', 'render-graph-execution.js', 'apply-template.js'];
for (const kind of ['flow-write', 'evaluation-fsync']) test(`cancellation remains responsive while ${kind} blocks the storage worker`, { skip: process.platform !== 'linux' }, async () => {
  const fixture = fs.mkdtempSync(path.join(os.tmpdir(), 'storage-cancel-')), copy = path.join(fixture, 'runtime'), project = path.join(fixture, 'project'), system = path.join(project, '.knowledge');
  fs.cpSync(source, copy, { recursive: true }); fs.mkdirSync(path.join(system, 'tools'), { recursive: true });
  fs.writeFileSync(path.join(system, 'config.yaml'), 'updates:\n  enabled: false\n'); fs.writeFileSync(path.join(system, 'package.json'), '{"version":"3.4.4"}');
  for (const file of commands) fs.writeFileSync(path.join(system, 'tools', file), 'console.log(JSON.stringify({status:"ok"}));\n');
  const context = resolveKnowledgeContext({ __skipCli: true, mode: 'repo', systemRoot: system, targetRoot: project, projectKnowledgeRoot: system });
  fs.writeFileSync(path.join(fixture, 'context.json'), JSON.stringify(context));
  const target = path.join(copy, 'tools/lib/json-store.js'), original = fs.readFileSync(target, 'utf8');
  const needle = "const fs = require('fs');"; assert.ok(original.includes(needle));
  const hook = `\n// EXPLICIT TEST-ONLY STORAGE HOLD; not an actual kernel I/O stall.\n{
    const realWrite=fs.writeFileSync, realSync=fs.fsyncSync;
    const blocked=file=>{const name=typeof file==='number'?fs.readlinkSync('/proc/self/fd/'+file):String(file);
      if(name.includes(${JSON.stringify(kind === 'flow-write' ? '/maintenance/flow-logs/' : '/evaluation/results/')})){
        realWrite(${JSON.stringify(path.join(fixture, 'blocked.json'))},JSON.stringify({pid:process.pid,proc_pid:Number(fs.readlinkSync('/proc/self')),kind:${JSON.stringify(kind)}}));
        Atomics.wait(new Int32Array(new SharedArrayBuffer(4)),0,0);
      }};
    ${kind === 'flow-write' ? 'fs.writeFileSync=function(file,...args){blocked(file);return realWrite.call(fs,file,...args)};' : 'fs.fsyncSync=function(fd){blocked(fd);return realSync.call(fs,fd)};'}
  }\n`;
  fs.writeFileSync(target, original.replace(needle, needle + hook));
  const prior = '{"preserved":"prior complete report"}\n';
  if (kind === 'evaluation-fsync') { fs.mkdirSync(path.join(system, 'evaluation/results'), { recursive: true }); fs.writeFileSync(path.join(system, 'evaluation/results/latest.json'), prior); }
  try {
    const helper = require('../tools/lib/verification-linux-namespace').preparePackagedHelper();
    const result = await runner.runOwnedCommand({ executable: process.execPath,
      args: [path.join(__dirname, 'helpers/reliability-storage-observer.cjs'), copy, fixture, kind, helper.executable],
      cwd: fixture, env: process.env, nestedAuthority: true }, { budgets: { workMs: 30000, setupMs: 10000, cleanupMs: 10000 } });
    assert.equal(result.cleanup.status, 'completed', JSON.stringify(result)); assert.equal(result.status, 0, JSON.stringify(result));
    const observed = JSON.parse(result.stdout);
    console.log(JSON.stringify({ source, original_json_store_sha256: hash(original), instrumented_json_store_sha256: hash(fs.readFileSync(target)), ...observed }));
    assert.equal(observed.status, 'pass'); assert.equal(observed.forced_test_kill, false);
    assert.notEqual(observed.blocked_writer.proc_pid, observed.caller.proc_pid);
    assert.ok(observed.exits.some(row => row.identity.namespace_pid === 1));
    if (kind === 'evaluation-fsync') assert.equal(fs.readFileSync(path.join(system, 'evaluation/results/latest.json'), 'utf8'), prior);
  } finally { fs.rmSync(fixture, { recursive: true, force: true }); }
});
