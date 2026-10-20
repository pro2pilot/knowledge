'use strict';
// Actual Inspector collection/render/build with persisted task routing. The
// existing routing suite is reused only for fixture seeds, never its verdicts.
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { withTempFixture } = require('../tools/lib/strict-temp-cleanup');
const system = path.resolve(__dirname, '..');
const write = (file, value) => {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, typeof value === 'string' ? value : JSON.stringify(value, null, 2) + '\n');
};

function inspectorFixture(run) {
  return withTempFixture({ prefix: 'knowledge-inspector-evidence-' }, owned => {
    const envKeys = Object.keys(process.env).filter(key => /^(KNOWLEDGE_|OPENAI_|MEM0_|PINECONE_)/i.test(key) || ['TMPDIR', 'TMP', 'TEMP'].includes(key));
    const savedEnv = Object.fromEntries(envKeys.map(key => [key, process.env[key]]));
    const child = require('node:child_process'), originals = new Map(), attempts = [];
    const replace = (object, key, api) => {
      if (!originals.has(object)) originals.set(object, new Map());
      originals.get(object).set(key, object[key]);
      object[key] = () => { attempts.push(api); throw new Error('Inspector test forbids child/network: ' + api); };
    };
    for (const key of ['spawn', 'spawnSync', 'exec', 'execSync', 'execFile', 'execFileSync', 'fork']) replace(child, key, 'child.' + key);
    for (const protocol of ['node:http', 'node:https']) for (const key of ['get', 'request']) replace(require(protocol), key, protocol + '.' + key);
    replace(global, 'fetch', 'fetch');
    try {
      for (const key of envKeys) delete process.env[key];
      const kit = path.join(owned, 'system', '.knowledge'), temp = path.join(owned, 'tmp');
      fs.mkdirSync(temp, { recursive: true });
      for (const key of ['TMPDIR', 'TMP', 'TEMP']) process.env[key] = temp;
      Object.assign(process.env, { KNOWLEDGE_DISABLE_GIT_DISCOVERY: '1', KNOWLEDGE_AGENT_ID: 'inspector-evidence-test', KNOWLEDGE_UPDATE_DISABLE_ON_LAUNCH: '1' });
      fs.cpSync(path.join(system, 'tools'), path.join(kit, 'tools'), { recursive: true });
      fs.cpSync(path.join(system, 'schemas'), path.join(kit, 'schemas'), { recursive: true });
      fs.copyFileSync(path.join(system, 'package.json'), path.join(kit, 'package.json'));
      const text = fs.readFileSync(path.join(kit, 'tools/self-test-task-routing.js'), 'utf8');
      const seed = text.slice(text.indexOf('function write('), text.indexOf('function main()'));
      assert(seed.startsWith('function write(') && seed.includes('function fixture('));
      const helper = path.join(kit, 'tools/inspector-fixture-seed.cjs');
      write(helper, "'use strict';const fs=require('fs'),os=require('os'),path=require('path');const routing=require('./lib/task-routing');\n" + seed + '\nmodule.exports={fixture};\n');
      const f = require(helper).fixture();
      assert(f.root.startsWith(temp + path.sep));
      Object.assign(process.env, { KNOWLEDGE_SYSTEM_ROOT: kit, KNOWLEDGE_PROJECT_KNOWLEDGE_ROOT: f.knowledge, KNOWLEDGE_TARGET_ROOT: f.root, KNOWLEDGE_STATE_ROOT: f.knowledge, KNOWLEDGE_MODE: 'repo' });
      write(path.join(f.knowledge, 'config.yaml'), 'updates:\n  enabled: false\n');
      const trustFile = path.join(f.knowledge, 'maintenance/trust_report.json'), trust = JSON.parse(fs.readFileSync(trustFile));
      trust.status = 'healthy'; write(trustFile, trust);
      write(path.join(f.knowledge, 'maintenance/quality_report.json'), { status: 'healthy', quality_score: 100, contradictions: [], issues: [] });
      write(path.join(f.knowledge, 'maintenance/repair_queue.json'), { queue: [] });
      write(path.join(f.knowledge, 'maintenance/stale_items.json'), { items: [] });
      f.context = require(path.join(kit, 'tools/lib/path-context')).resolveKnowledgeContext({ __skipCli: true });
      f.routing = require(path.join(kit, 'tools/lib/task-routing'));
      f.resolve = require(path.join(kit, 'tools/lib/task-routing-state')).resolveEffectiveTaskRoutingState;
      f.inspector = require(path.join(kit, 'tools/build-visual-inspector'));
      f.create = (scopeSource = 'explicit') => f.routing.create(f.context, { task: 'Audit and update only the Pro2Pilot knowledge website', taskClass: 'content_consistency_audit', modules: ['pro2pilot'], paths: ['pro2pilot/'], scopeSource });
      f.task = (model, created) => model.taskRouting.tasks.find(item => item.task_scope_hash === created.task_scope_hash);
      f.effective = created => f.resolve({ context: f.context, taskScopeHash: created.task_scope_hash, verifyLiveInputs: true, readOnly: true });
      const result = run(f);
      assert.deepEqual(attempts, []);
      return result;
    } finally {
      for (const [object, entries] of originals) for (const [key, value] of entries) object[key] = value;
      for (const key of Object.keys(process.env)) if (/^(KNOWLEDGE_|OPENAI_|MEM0_|PINECONE_)/i.test(key) || ['TMPDIR', 'TMP', 'TEMP'].includes(key)) delete process.env[key];
      Object.assign(process.env, savedEnv);
      for (const name of Object.keys(require.cache)) if (name.startsWith(owned + path.sep)) delete require.cache[name];
    }
  });
}

function assertReady(html) {
  assert.match(html, /<strong>Ready to work<\/strong>/);
  assert.doesNotMatch(html, /<strong>Task evidence needs recheck<\/strong>/);
}

test('Inspector keeps a valid current task ready with unchanged healthy reports', () => inspectorFixture(f => {
  const created = f.create(), effective = f.effective(created), model = f.inspector.collect({ readOnly: true });
  assert.equal(effective.current_status, 'current'); assert.equal(effective.live_inputs_match, true);
  assert.equal(f.task(model, created).claim_eligible, true);
  assertReady(f.inspector.renderTabbed(model));
  f.inspector({ quiet: true });
  assertReady(fs.readFileSync(path.join(f.knowledge, 'inspector/index.html'), 'utf8'));
}));

test('Inspector warns after task source drift despite healthy cached reports', () => inspectorFixture(f => {
  const created = f.create();
  const reports = ['maintenance/trust_report.json', 'maintenance/quality_report.json'].map(name => [path.join(f.knowledge, name), fs.readFileSync(path.join(f.knowledge, name))]);
  assertReady(f.inspector.renderTabbed(f.inspector.collect({ readOnly: true })));
  fs.appendFileSync(path.join(f.root, 'pro2pilot/knowledge.html'), '\nchanged bound source\n');
  assert.equal(f.effective(created).live_inputs_match, false);
  const model = f.inspector.collect({ readOnly: true }), task = f.task(model, created);
  assert.equal(task.claim_eligible, false); assert(task.claim_ineligible_reasons.includes('live_relevant_input_drift'));
  assert.equal(task.estimated_tokens_saved, null); assert.equal(task.estimated_tokens_overhead, null);
  assert.equal(model.trust.status, 'healthy'); assert.equal(model.quality.quality_score, 100);
  const verify = html => {
    assert.match(html, /<strong>Task evidence needs recheck<\/strong>/);
    assert.match(html, /<strong>Recheck task evidence before relying on summaries<\/strong>/);
    assert.doesNotMatch(html, /<strong>Ready to work<\/strong>/);
    assert.match(html, /claim ineligible/);
    assert.match(html, /node \.knowledge\/tools\/task-routing\.js list --json/);
  };
  verify(f.inspector.renderTabbed(model));
  f.inspector({ quiet: true }); verify(fs.readFileSync(path.join(f.knowledge, 'inspector/index.html'), 'utf8'));
  assert.equal(f.task(JSON.parse(fs.readFileSync(path.join(f.knowledge, 'inspector/data.json'))), created).claim_eligible, false);
  for (const [file, content] of reports) assert.deepEqual(fs.readFileSync(file), content);
}));

test('Inspector does not turn an estimator scope limitation into stale task evidence', () => inspectorFixture(f => {
  const created = f.create('inferred'), state = f.effective(created), model = f.inspector.collect({ readOnly: true });
  assert.equal(state.current_status, 'current'); assert.equal(state.live_inputs_match, true); assert.equal(state.task_readiness, 'ready');
  assert.equal(state.snapshot_complete, true); assert.equal(state.required_sources_complete, true); assert.equal(state.required_continuations_complete, true);
  assert.equal(f.task(model, created).claim_eligible, false); assert(f.task(model, created).claim_ineligible_reasons.includes('requires_explicit_frozen_scope'));
  assertReady(f.inspector.renderTabbed(model));
  f.inspector({ quiet: true }); assertReady(fs.readFileSync(path.join(f.knowledge, 'inspector/index.html'), 'utf8'));
}));

test('Inspector keeps dangerous graph/provider labels inert in render and written output', () => inspectorFixture(f => {
  const payload = 'Inspector text </script><script data-test-injection="yes">throw "injected"</script><img src=x onerror="injected"> & \' "';
  const registryFile = path.join(f.knowledge, 'modules/module_registry.json'), registry = JSON.parse(fs.readFileSync(registryFile));
  registry.modules.find(item => item.module_id === 'pro2pilot').name = payload; write(registryFile, registry);
  write(path.join(f.knowledge, 'maps/wiki_graph.json'), { structural_status: 'healthy', nodes: [{ id: 'module:pro2pilot', type: 'module', title: payload, module_id: 'pro2pilot', path: '.knowledge/modules/pro2pilot.json', trust: 'trusted' }], edges: [] });
  write(path.join(f.knowledge, 'maintenance/external_memory_status.json'), { providers: [{ provider_id: 'mem0-oss', status: 'not_ready', warnings: [payload] }] });
  const data = f.inspector.collect({ readOnly: true }); assert.equal(data.external.providers[0].warnings[0], payload);
  const verify = html => {
    assert.doesNotMatch(html, /<script data-test-injection=/); assert.doesNotMatch(html, /<img src=x onerror=/);
    assert.match(html, /&lt;\/script&gt;/); assert.match(html, /data-graph-detail-json=/);
    const scripts = [...html.matchAll(/<script\b[^>]*>([\s\S]*?)<\/script>/gi)].map(match => match[1]);
    assert.equal(scripts.length, 1); for (const source of scripts) new vm.Script(source);
  };
  data.context.git.branches = { current: payload, local: [payload] };
  const rendered = f.inspector.renderTabbed(data); verify(rendered); assert(rendered.includes('\\u003c/script>'));
  f.inspector({ quiet: true }); verify(fs.readFileSync(path.join(f.knowledge, 'inspector/index.html'), 'utf8'));
}));
