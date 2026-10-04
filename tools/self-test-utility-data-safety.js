#!/usr/bin/env node
'use strict';

// Black-box regression tests for data preservation, honest search results,
// session concurrency, and local memory export/record integrity.
const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync, spawn } = require('child_process');
const { systemVersion } = require('./lib/system-version');

const source = path.resolve(__dirname, '..');
const root = fs.mkdtempSync(path.join(os.tmpdir(), 'knowledge-utility-safety-'));
const checks = [];
const env = { ...process.env };
for (const key of Object.keys(env)) {
  if (/^(KNOWLEDGE_|PINECONE_|OPENAI_|MEM0_)/i.test(key)) delete env[key];
}
Object.assign(env, { CI: '1', KNOWLEDGE_AGENT_ID: 'utility-safety-test', KNOWLEDGE_FLOW_NO_OPEN: '1', KNOWLEDGE_INSPECTOR_NO_OPEN: '1' });

function fixture(name) {
  const target = path.join(root, name);
  const kit = path.join(target, '.knowledge');
  fs.cpSync(source, kit, { recursive: true, filter: (file) => {
    const relative = path.relative(source, file).replace(/\\/g, '/');
    return !/^(?:\.git|node_modules|\.self-test-tmp|\.qa-tmp)(?:\/|$)/.test(relative);
  } });
  const config = path.join(kit, 'config.yaml');
  if (fs.existsSync(config)) fs.writeFileSync(config, fs.readFileSync(config, 'utf8').replace('updates:\n  enabled: true', 'updates:\n  enabled: false'));
  return target;
}
function file(target, relative) { return path.join(target, '.knowledge', relative); }
function write(target, relative, content) {
  const dest = file(target, relative);
  fs.mkdirSync(path.dirname(dest), { recursive: true });
  fs.writeFileSync(dest, typeof content === 'string' ? content : JSON.stringify(content));
  return dest;
}
function cli(target, tool, args = [], expected = 0) {
  const result = spawnSync(process.execPath, [file(target, `tools/${tool}`), ...args], { cwd: target, env, encoding: 'utf8', timeout: 60000, windowsHide: true });
  if (expected === 'reject') assert.notStrictEqual(result.status, 0, `${tool} accepted unsafe input: ${result.stdout}`);
  else assert.strictEqual(result.status, expected, `${tool} failed: ${result.stderr}\n${result.stdout}`);
  let value = null;
  try { value = JSON.parse(result.stdout); } catch {}
  return { ...result, value };
}
async function check(name, run) {
  try { await run(); checks.push({ name, status: 'pass' }); }
  catch (error) { checks.push({ name, status: 'fail', error: error.message }); }
}
function template(target, id, pages) {
  write(target, `templates/official/${id}/template.json`, { id, name: id, wiki_pages: pages, critical_paths: [] });
}
function sessionChild(target, id) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [file(target, 'tools/agent-session.js'), 'start', '--session-id', id, '--json'], { cwd: target, env, windowsHide: true });
    let stdout = '', stderr = '';
    child.stdout.on('data', (chunk) => { stdout += chunk; });
    child.stderr.on('data', (chunk) => { stderr += chunk; });
    child.on('error', reject);
    child.on('close', (code) => code === 0 ? resolve(stdout) : reject(new Error(`session ${id}: ${code}: ${stderr}`)));
  });
}

async function main() {
  await check('template removal preserves skipped pre-existing pages', () => {
    const target = fixture('preexisting');
    const own = write(target, 'wiki/architecture/fastapi-service-boundaries.md', '# User-owned original\n');
    cli(target, 'apply-template.js', ['python-fastapi']);
    cli(target, 'apply-template.js', ['python-fastapi']);
    cli(target, 'apply-template.js', ['--remove', 'python-fastapi']);
    assert.strictEqual(fs.readFileSync(own, 'utf8'), '# User-owned original\n');
    assert(!fs.existsSync(file(target, 'wiki/runbooks/fastapi-agent-review.md')));
  });
  await check('template removal preserves pages modified after apply', () => {
    const target = fixture('modified');
    cli(target, 'apply-template.js', ['python-fastapi']);
    const own = write(target, 'wiki/architecture/fastapi-service-boundaries.md', '# Edited by the project owner\n');
    const removed = cli(target, 'apply-template.js', ['--remove', 'python-fastapi']).value.results[0];
    assert.strictEqual(fs.readFileSync(own, 'utf8'), '# Edited by the project owner\n');
    assert.strictEqual(removed.wiki_pages_deleted, 1);
    assert(removed.wiki_pages_preserved.some((item) => item.reason === 'modified_since_apply'));
  });
  await check('legacy template records cannot prove page ownership', () => {
    const target = fixture('legacy');
    cli(target, 'apply-template.js', ['python-fastapi']);
    const registryPath = file(target, 'maintenance/applied_templates.json');
    const registry = JSON.parse(fs.readFileSync(registryPath));
    delete registry.templates[0].wiki_page_hashes;
    fs.writeFileSync(registryPath, JSON.stringify(registry));
    cli(target, 'apply-template.js', ['--remove', 'python-fastapi']);
    assert(fs.existsSync(file(target, 'wiki/architecture/fastapi-service-boundaries.md')));
  });
  await check('--diff and --dry-run leave pages and metadata unchanged', () => {
    const target = fixture('preview');
    const before = fs.existsSync(file(target, 'project_index.json')) ? fs.readFileSync(file(target, 'project_index.json'), 'utf8') : null;
    for (const flag of ['--diff', '--dry-run']) cli(target, 'apply-template.js', ['python-fastapi', flag]);
    assert(!fs.existsSync(file(target, 'wiki/runbooks/fastapi-agent-review.md')));
    const after = fs.existsSync(file(target, 'project_index.json')) ? fs.readFileSync(file(target, 'project_index.json'), 'utf8') : null;
    assert.strictEqual(after, before);
  });
  await check('template manifest traversal is rejected before file writes', () => {
    const target = fixture('template-escape');
    template(target, 'audit-escape', { 'wiki/ok.md': '# safe', '../escaped.md': '# outside' });
    cli(target, 'apply-template.js', ['audit-escape'], 'reject');
    assert(!fs.existsSync(path.join(target, 'escaped.md')));
    assert(!fs.existsSync(file(target, 'wiki/ok.md')));
  });
  await check('template id traversal and unknown flags reject', () => {
    const target = fixture('template-invalid');
    cli(target, 'apply-template.js', ['../other'], 'reject');
    cli(target, 'apply-template.js', ['--remove'], 'reject');
    cli(target, 'apply-template.js', ['--unknown'], 'reject');
  });
  await check('template removal rejects unsafe registry paths', () => {
    const target = fixture('registry-escape');
    const outside = path.join(target, 'user-owned.md');
    fs.writeFileSync(outside, 'preserve me');
    write(target, 'maintenance/applied_templates.json', { templates: [{ id: 'bad', wiki_pages: ['../user-owned.md'] }] });
    cli(target, 'apply-template.js', ['--remove', 'bad'], 'reject');
    assert.strictEqual(fs.readFileSync(outside, 'utf8'), 'preserve me');
  });
  await check('template metadata symlinks are rejected before creating wiki pages', () => {
    const target = fixture('template-symlink');
    const outside = path.join(root, 'outside-repair.json');
    fs.writeFileSync(outside, '{"queue":[]}');
    fs.mkdirSync(file(target, 'maintenance'), { recursive: true });
    fs.rmSync(file(target, 'maintenance/repair_queue.json'), { force: true });
    fs.symlinkSync(outside, file(target, 'maintenance/repair_queue.json'));
    cli(target, 'apply-template.js', ['python-fastapi'], 'reject');
    assert.strictEqual(fs.readFileSync(outside, 'utf8'), '{"queue":[]}');
    assert(!fs.existsSync(file(target, 'wiki/runbooks/fastapi-agent-review.md')));
  });
  await check('template repair items use unique ids and preserve unrelated items', () => {
    const target = fixture('repair-ownership');
    write(target, 'maintenance/repair_queue.json', { queue: [{ id: 'TPL-0002', subject: 'User repair' }] });
    cli(target, 'apply-template.js', ['python-fastapi']);
    const queue = JSON.parse(fs.readFileSync(file(target, 'maintenance/repair_queue.json'))).queue;
    assert.strictEqual(new Set(queue.map((item) => item.id)).size, queue.length);
    const applied = JSON.parse(fs.readFileSync(file(target, 'maintenance/applied_templates.json')));
    applied.templates[0].repair_items.push('TPL-0002');
    write(target, 'maintenance/applied_templates.json', applied);
    cli(target, 'apply-template.js', ['--remove', 'python-fastapi']);
    assert(JSON.parse(fs.readFileSync(file(target, 'maintenance/repair_queue.json'))).queue.some((item) => item.subject === 'User repair'));
  });
  await check('corrupt template metadata is preserved and stops all page writes', () => {
    for (const relative of ['maintenance/repair_queue.json', 'maintenance/applied_templates.json', 'project_index.json']) {
      const target = fixture(`template-corrupt-${path.basename(relative)}`);
      const damaged = write(target, relative, '{"unfinished":');
      cli(target, 'apply-template.js', ['python-fastapi'], 'reject');
      assert.strictEqual(fs.readFileSync(damaged, 'utf8'), '{"unfinished":');
      assert(!fs.existsSync(file(target, 'wiki/runbooks/fastapi-agent-review.md')));
    }
  });

  const search = fixture('search café Україна');
  write(search, 'wiki/audit-language.md', '# 認証 їжак café\n\n認証システム їжак café language fixtures with exact source terminology.\n');
  cli(search, 'build-search-index.js');
  await check('unrelated search has no fabricated hits', () => {
    assert.deepStrictEqual(cli(search, 'search-knowledge.js', ['doesnotexistzxqv20261003', '--json']).value.results, []);
    assert.deepStrictEqual(cli(search, 'search-knowledge.js', ['???', '--json']).value.results, []);
  });
  await check('search matches Unicode text and normalized accents', () => {
    for (const query of ['認証', 'їжак', 'cafe\u0301']) {
      const value = cli(search, 'search-knowledge.js', [query, '--json']).value;
      assert(value.base_terms.length > 0);
      assert(value.results.some((item) => item.path === '.knowledge/wiki/audit-language.md'), query);
    }
  });
  await check('search validates limits, scopes, flags and separates context arguments', () => {
    for (const arg of ['--limit=NaN', '--limit=0', '--limit=1.5', '--limit=Infinity', '--scope=missing', '--unknown']) cli(search, 'search-knowledge.js', ['auth', arg, '--json'], 'reject');
    const value = cli(search, 'search-knowledge.js', ['認証', '--target-root', search, '--limit', '1', '--json']).value;
    assert.strictEqual(value.query, '認証');
    assert.strictEqual(value.results.length, 1);
  });
  await check('corrupt search index fails without rewriting the damaged file', () => {
    const damaged = write(search, 'search/index.json', '{"documents":');
    cli(search, 'search-knowledge.js', ['auth', '--json'], 'reject');
    assert.strictEqual(fs.readFileSync(damaged, 'utf8'), '{"documents":');
  });

  await check('agent session ids reject traversal and platform-dangerous segments', () => {
    const target = fixture('session-invalid');
    for (const value of ['../../../escaped-session', '..\\escaped', 'CON', 'name.', 'a:b']) cli(target, 'agent-session.js', ['start', '--session-id', value, '--json'], 'reject');
    assert(!fs.existsSync(path.join(target, 'escaped-session.json')));
    const valid = cli(target, 'agent-session.js', ['start', '--session-id', 'сессия café', '--json']).value;
    assert.strictEqual(valid.session.session_id, 'сессия café');
  });
  await check('session registry symlink cannot overwrite outside state', () => {
    const target = fixture('session-symlink');
    const outside = path.join(root, 'outside-sessions.json');
    fs.writeFileSync(outside, '{"sessions":[]}');
    fs.mkdirSync(file(target, 'sessions'), { recursive: true });
    fs.rmSync(file(target, 'sessions/agent-registry.json'), { force: true });
    fs.symlinkSync(outside, file(target, 'sessions/agent-registry.json'));
    cli(target, 'agent-session.js', ['start', '--session-id', 'new-session', '--json'], 'reject');
    assert.strictEqual(fs.readFileSync(outside, 'utf8'), '{"sessions":[]}');
    assert(!fs.existsSync(file(target, 'sessions/agents/new-session.json')));
  });
  await check('corrupt session registry rejects before writing a new session file', () => {
    const target = fixture('session-corrupt');
    write(target, 'sessions/agent-registry.json', '{"sessions":');
    cli(target, 'agent-session.js', ['start', '--session-id', 'new-session', '--json'], 'reject');
    assert(!fs.existsSync(file(target, 'sessions/agents/new-session.json')));
  });
  await check('32 concurrent successful session starts retain 32 registry entries', async () => {
    const target = fixture('concurrent-sessions');
    for (let offset = 0; offset < 32; offset += 16) {
      // Wait for every owned worker before inspecting state or cleaning up.
      const results = await Promise.allSettled(Array.from({ length: 16 }, (_, index) => sessionChild(target, `concurrent-${offset + index}`)));
      const failed = results.filter(result => result.status === 'rejected');
      assert.strictEqual(failed.length, 0, failed.map(result => result.reason.message).join('\n'));
    }
    const registry = JSON.parse(fs.readFileSync(file(target, 'sessions/agent-registry.json')));
    assert.strictEqual(registry.sessions.length, 32);
    assert.strictEqual(new Set(registry.sessions.map((item) => item.session_id)).size, 32);
    assert.strictEqual(fs.readdirSync(file(target, 'sessions/agents')).filter((name) => name.endsWith('.json')).length, 32);
  });

  await check('corrupt local memory rejects add and forget without data loss', () => {
    const target = fixture('memory-corrupt');
    const original = '{"id":"valid","text":"old record"}\n{"id":"partial"\n';
    const store = write(target, 'external_memory/mem0/adapter-records.jsonl', original);
    for (const args of [['add', '--text', 'new text'], ['forget', '--id', 'valid']]) {
      cli(target, 'memory-mem0.js', [...args, '--adapter', 'test', '--json'], 'reject');
      assert.strictEqual(fs.readFileSync(store, 'utf8'), original);
    }
  });
  await check('local memory symlink refuses reads and writes outside state', () => {
    const target = fixture('memory-symlink');
    const outside = path.join(root, 'outside-memory');
    fs.mkdirSync(outside);
    fs.writeFileSync(path.join(outside, 'adapter-records.jsonl'), '{"id":"outside","text":"keep"}\n');
    fs.mkdirSync(file(target, 'external_memory'), { recursive: true });
    fs.rmSync(file(target, 'external_memory/mem0'), { force: true, recursive: true });
    fs.symlinkSync(outside, file(target, 'external_memory/mem0'), 'dir');
    cli(target, 'memory-mem0.js', ['add', '--adapter', 'test', '--text', 'new', '--json'], 'reject');
    assert.strictEqual(fs.readFileSync(path.join(outside, 'adapter-records.jsonl'), 'utf8'), '{"id":"outside","text":"keep"}\n');
  });
  await check('local memory round trip remains advisory and export removes metadata content', () => {
    const target = fixture('memory-roundtrip');
    const metadata = { text: 'private-metadata-content', [['private', 'key'].join('_')]: 'key-canary', user_email: ['audit', 'example.invalid'].join('@'), source_of_truth: true };
    const added = cli(target, 'memory-mem0.js', ['add', '--adapter', 'test', '--text', 'mémoire локальная', '--metadata-json', JSON.stringify(metadata), '--json']).value;
    assert.strictEqual(added.persisted, true);
    assert.strictEqual(added.source_of_truth, false);
    const recalled = cli(target, 'memory-mem0.js', ['recall', 'mémoire', '--adapter', 'test', '--json']).value;
    assert.strictEqual(recalled.results.length, 1);
    const exported = cli(target, 'memory-mem0.js', ['export-redacted', '--adapter', 'test', '--json']);
    for (const canary of ['private-metadata-content', 'key-canary', 'mémoire локальная', ['audit', 'example.invalid'].join('@')]) assert(!exported.stdout.includes(canary), canary);
    assert.strictEqual(exported.value.records_count, 1);
    assert.strictEqual(exported.value.source_of_truth, false);
    const deleted = cli(target, 'memory-mem0.js', ['forget', '--id', added.record.id, '--adapter', 'test', '--json']).value;
    assert.strictEqual(deleted.deleted, true);
  });

  const failed = checks.filter((item) => item.status !== 'pass');
  console.log(JSON.stringify({ schema_version: systemVersion(), status: failed.length ? 'fail' : 'pass', total: checks.length, passed: checks.length - failed.length, failed: failed.length, checks, retained_fixture: failed.length ? root : null }, null, 2));
  process.exitCode = failed.length ? 1 : 0;
}

main().catch((error) => { console.error(error.stack || error.message); process.exitCode = 1; }).finally(() => {
  if (!process.exitCode && !process.argv.includes('--keep-temp')) fs.rmSync(root, { recursive: true, force: true });
});
