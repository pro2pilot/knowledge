'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawn } = require('node:child_process');
const { test } = require('node:test');
const source = path.resolve(process.env.KNOWLEDGE_AUDIT_SOURCE_ROOT || path.join(__dirname, '..'));
const modulePath = path.join(source, 'tools/lib/report-generation.js');
const generation = fs.existsSync(modulePath) ? require(modulePath) : null;
const { captureTempDirIdentity, removeTempDirStrict } = require(path.join(source, 'tools/lib/strict-temp-cleanup'));

const worker = String.raw`
const fs=require('node:fs'),path=require('node:path');
const [source,project,state,command,fault]=process.argv.slice(1);
for(const key of Object.keys(process.env))if(key.startsWith('KNOWLEDGE_'))delete process.env[key];
Object.assign(process.env,{KNOWLEDGE_SYSTEM_ROOT:source,KNOWLEDGE_PROJECT_KNOWLEDGE_ROOT:path.join(project,'.knowledge'),KNOWLEDGE_TARGET_ROOT:project,KNOWLEDGE_STATE_ROOT:state,KNOWLEDGE_DISABLE_GIT_DISCOVERY:'1'});
const first=command==='collect-metrics'?'baseline.json':'data.json',last=command==='collect-metrics'?'README.md':'index.html';
const original=fs.renameSync;
fs.renameSync=function(from,to){
 if(fault==='enospc'&&path.basename(to)===last)throw Object.assign(new Error('injected ENOSPC at second compatibility view'),{code:'ENOSPC'});
 const value=original.apply(this,arguments);
 if(fault==='kill'&&path.basename(to)===first){fs.writeSync(1,'CRASH_BOUNDARY\n');Atomics.wait(new Int32Array(new SharedArrayBuffer(4)),0,0,120000);}
 return value;
};
console.log=()=>{};
let result,error;
try {const run=require(path.join(source,'tools',command+'.js')); result=command==='build-visual-inspector'?run({quiet:true,skipLock:true}):run();}
catch(e){error={code:e.code||null,message:e.message,report_publication:e.report_publication||null};}
if(fault==='kill'){setTimeout(()=>process.exit(4),120000);}
else process.send({result,error},()=>process.disconnect());
`;

function fixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'knowledge-generation-'));
  const identity = captureTempDirIdentity(root);
  t.after(() => removeTempDirStrict(root, { expectedIdentity: identity }));
  const project = path.join(root, 'project'), state = path.join(root, 'state');
  for (const dir of [path.join(project, '.knowledge'), path.join(state, 'maintenance')]) fs.mkdirSync(dir, { recursive: true });
  return { root, project, state };
}
function run(f, command, fault = '') {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ['-e', worker, source, f.project, f.state, command, fault], { stdio: ['ignore', 'pipe', 'pipe', 'ipc'], windowsHide: true });
    let message, stderr = '', killed = false, failure;
    const timeout = setTimeout(() => { failure = new Error('Driver deadline exceeded'); child.kill('SIGKILL'); }, 60000);
    child.stdout.on('data', b => { if (fault === 'kill' && b.toString().includes('CRASH_BOUNDARY')) { killed = true; child.kill('SIGKILL'); } });
    child.stderr.on('data', b => { stderr += b.toString(); });
    child.on('error', e => { failure = e; });
    child.on('message', m => {
      message = m;
      if (m.boundary && fault === 'kill') { killed = true; child.kill('SIGKILL'); }
    });
    child.on('close', (code, signal) => {
      clearTimeout(timeout);
      if (failure) return reject(failure);
      try {
        if (fault === 'kill') { assert.equal(killed, true, stderr); assert.ok(code !== 0 || signal !== null, 'Crash must be physically observed'); }
        else assert.equal(code, 0, stderr);
        resolve({ ...message, code, signal, killed });
      } catch (e) { reject(e); }
    });
  });
}
function views(f, command) {
  const group = command === 'collect-metrics' ? 'metrics' : 'inspector';
  const names = command === 'collect-metrics' ? ['baseline.json', 'README.md'] : ['data.json', 'index.html', 'status.json'];
  if (generation) return generation.readReportGeneration(f.state, path.join(f.state, group)).files;
  return Object.fromEntries(names.map(name => [name, fs.readFileSync(path.join(f.state, group, name))]));
}
function coherent(files, command) {
  const data = JSON.parse(files[command === 'collect-metrics' ? 'baseline.json' : 'data.json']);
  if (command === 'collect-metrics') assert.ok(files['README.md'].toString().includes(`Generated: ${data.generated_at}`), 'JSON and Markdown must belong to one committed generation');
  else {
    assert.equal(JSON.parse(files['status.json']).generated_at, data.generated_at, 'Inspector status and data must belong to one generation');
    assert.ok(files['index.html'].toString().includes(data.generated_at), 'Inspector HTML and data must belong to one generation');
  }
  return data.generated_at;
}
for (const command of ['collect-metrics', 'build-visual-inspector']) for (const fault of ['enospc', 'kill']) {
  test(`coherent ${command} after ${fault} during view publication`, { timeout: 90000 }, async t => {
    const f = fixture(t);
    const first = await run(f, command);
    assert.equal(first.error, undefined, JSON.stringify(first));
    const before = coherent(views(f, command), command);
    fs.writeFileSync(path.join(f.state, 'maintenance/quality_report.json'), JSON.stringify({ quality_score: 17, status: 'warning' }));
    const after = await run(f, command, fault);
    const observed = coherent(views(f, command), command);
    assert.notEqual(observed, before, 'Fault occurs after the new committed generation is available');
    if (generation && fault === 'enospc') {
      assert.equal(after.error, undefined, JSON.stringify(after));
      assert.equal(after.result.publication.commit_state, 'committed');
      assert.equal(after.result.publication.mirrors_complete, false);
      assert.equal(after.result.publication.mirror_errors[0].code, 'ENOSPC');
    }
  });
}

test('commit failure preserves the previous complete report', { skip: !generation }, t => {
  const f = fixture(t), dir = path.join(f.state, 'report');
  const before = generation.publishReportGeneration(f.state, dir, { 'a.json': '{"value":1}', 'b.txt': 'one' });
  assert.throws(() => generation.publishReportGeneration(f.state, dir, { 'a.json': '{"value":2}', 'b.txt': 'two' }, {
    writeHooks: { renameSync() { throw Object.assign(new Error('full filesystem'), { code: 'ENOSPC' }); } }
  }), e => e.code === 'ENOSPC' && e.report_publication.commit_state === 'unconfirmed');
  const after = generation.readReportGeneration(f.state, dir);
  assert.equal(after.generation, before.generation);
  assert.equal(after.files['a.json'].toString(), '{"value":1}');
  assert.equal(after.files['b.txt'].toString(), 'one');
});
test('corrupt committed generation cannot fall back to a stale compatibility view', { skip: !generation }, t => {
  const f = fixture(t), dir = path.join(f.state, 'report');
  generation.publishReportGeneration(f.state, dir, { 'a.json': '{"value":1}' });
  const file = path.join(dir, generation.CURRENT), value = JSON.parse(fs.readFileSync(file));
  value.files['a.json'].body = '{"value":2}';
  fs.writeFileSync(file, JSON.stringify(value));
  assert.throws(() => generation.readReportJson(f.state, 'report', 'a.json', {}), { code: 'report_generation_invalid' });
});
test('missing commit after migration cannot expose a stale compatibility view', { skip: !generation }, t => {
  const f = fixture(t), dir = path.join(f.state, 'report');
  generation.publishReportGeneration(f.state, dir, { 'a.json': '{"value":1}' });
  fs.unlinkSync(path.join(dir, generation.CURRENT));
  assert.throws(() => generation.readReportJson(f.state, 'report', 'a.json', {}), { code: 'report_generation_missing' });
});
test('legacy single-file reports remain readable before migration', { skip: !generation }, t => {
  const f = fixture(t), dir = path.join(f.state, 'report'); fs.mkdirSync(dir);
  fs.writeFileSync(path.join(dir, 'a.json'), '{"legacy":true}');
  assert.deepEqual(generation.readReportJson(f.state, 'report', 'a.json', {}), { legacy: true });
  assert.deepEqual(generation.readReportJson(f.state, 'report', 'missing.json', { absent: true }), { absent: true });
});
test('all report views and commit are preflighted before the current generation changes', { skip: !generation }, t => {
  const f = fixture(t), dir = path.join(f.state, 'report');
  const before = generation.publishReportGeneration(f.state, dir, { 'a.json': '{}', 'b.txt': 'old' });
  fs.unlinkSync(path.join(dir, 'b.txt')); fs.mkdirSync(path.join(dir, 'b.txt'));
  assert.throws(() => generation.publishReportGeneration(f.state, dir, { 'a.json': '{"new":true}', 'b.txt': 'new' }));
  assert.equal(generation.readReportGeneration(f.state, dir).generation, before.generation);
});
test('snapshot replacement during read retries to a single intact generation', { skip: !generation }, t => {
  const f = fixture(t), dir = path.join(f.state, 'report');
  generation.publishReportGeneration(f.state, dir, { 'a.json': '{"v":1}', 'b.txt': 'one' });
  const replacement = path.join(dir, 'next.json');
  const value = JSON.parse(fs.readFileSync(path.join(dir, generation.CURRENT)));
  value.generation = 'a'.repeat(32);
  fs.writeFileSync(replacement, JSON.stringify(value));
  const original = fs.readSync; let swapped = false;
  fs.readSync = function() { const n = original.apply(this, arguments); if (!swapped) { swapped = true; fs.renameSync(replacement, path.join(dir, generation.CURRENT)); } return n; };
  try { assert.equal(generation.readReportGeneration(f.state, dir).generation, 'a'.repeat(32)); }
  finally { fs.readSync = original; }
});
test('growing snapshot reads stay bounded and fail closed', { skip: !generation }, t => {
  const f = fixture(t), dir = path.join(f.state, 'report');
  generation.publishReportGeneration(f.state, dir, { 'a.json': '{"v":1}' });
  const current = path.join(dir, generation.CURRENT), size = fs.statSync(current).size;
  const original = fs.readSync; let requested = 0;
  fs.readSync = function(fd, buffer, offset, length, position) { requested += length; fs.appendFileSync(current, 'x'.repeat(4096)); return original.apply(this, arguments); };
  try { assert.throws(() => generation.readReportGeneration(f.state, dir)); }
  finally { fs.readSync = original; }
  assert.ok(requested < (size + 4096 * 8) * 8, 'Read allocation and attempts remain finite under continuous growth');
});
for (const buffer of [false, true]) test('UTF-8 BOM bytes remain part of the committed ' + (buffer ? 'buffer' : 'string') + ' view', { skip: !generation }, t => {
  const f = fixture(t), dir = path.join(f.state, 'report');
  const text = '\uFEFF{"value":1}';
  generation.publishReportGeneration(f.state, dir, { 'a.json': buffer ? Buffer.from(text) : text });
  assert.deepEqual(generation.readReportGeneration(f.state, dir).files['a.json'], Buffer.from(text));
  assert.deepEqual(generation.readReportJson(f.state, 'report', 'a.json', {}), { value: 1 });
});
test('lock-layout names cannot be used as report views', { skip: !generation }, t => {
  const f = fixture(t), dir = path.join(f.state, 'report');
  assert.throws(() => generation.publishReportGeneration(f.state, dir, { locks: 'collision' }), { code: 'report_filename_invalid' });
});
test('migration fence survives a fault immediately after first commit', { skip: !generation }, t => {
  const f = fixture(t), dir = path.join(f.state, 'report'); fs.mkdirSync(dir);
  fs.writeFileSync(path.join(dir, 'a.json'), '{"stale":true}');
  assert.throws(() => generation.publishReportGeneration(f.state, dir, { 'a.json': '{"fresh":true}' }, {
    afterCommit() { throw Object.assign(new Error('after-commit interruption'), { code: 'INJECTED' }); }
  }), { code: 'INJECTED' });
  assert.deepEqual(generation.readReportJson(f.state, 'report', 'a.json', {}), { fresh: true });
  fs.unlinkSync(path.join(dir, generation.CURRENT));
  assert.throws(() => generation.readReportJson(f.state, 'report', 'a.json', {}), { code: 'report_generation_missing' });
});
