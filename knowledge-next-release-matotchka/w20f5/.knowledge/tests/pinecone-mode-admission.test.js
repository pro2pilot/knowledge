'use strict';

// Actual exported CLI entry point and pc.request, with an inert fetch transport.
// No Pinecone service, OS child, socket, or credentials are used by this suite.
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { captureTempDirIdentity, removeTempDirStrict } = require('../tools/lib/strict-temp-cleanup');
const system = path.resolve(__dirname, '..');
const cloud = { PINECONE_MODE: 'cloud', PINECONE_HOST: 'https://pinecone-fixture.invalid', PINECONE_API_KEY: 'pcsk_SYNTHETIC_ADMISSION_KEY' };
const operations = [['remember', '--text', 'Pinecone admission fixture'], ['recall', 'admission query'], ['sync-sources']];
const envKey = key => /^(KNOWLEDGE_|OPENAI_|MEM0_|PINECONE_)/i.test(key);

async function pineconeFixture(run) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'knowledge-pinecone-admission-'));
  const identity = captureTempDirIdentity(root), state = path.join(root, '.knowledge');
  const savedEnv = Object.fromEntries(Object.entries(process.env).filter(([key]) => envKey(key)));
  const cacheBefore = new Set(Object.keys(require.cache));
  const originals = new Map(), forbidden = [], calls = [];
  const replace = (object, key, value) => {
    if (!originals.has(object)) originals.set(object, new Map());
    originals.get(object).set(key, object[key]); object[key] = value;
  };
  const forbid = (object, key, api) => replace(object, key, () => {
    forbidden.push(api); throw new Error('Pinecone admission test forbids child/network: ' + api);
  });
  for (const key of ['spawn', 'spawnSync', 'exec', 'execSync', 'execFile', 'execFileSync', 'fork']) forbid(require('node:child_process'), key, 'child.' + key);
  for (const protocol of ['node:http', 'node:https']) for (const key of ['get', 'request']) forbid(require(protocol), key, protocol + '.' + key);
  for (const key of ['connect', 'createConnection']) forbid(require('node:net'), key, 'net.' + key);
  replace(console, 'log', () => {});
  replace(global, 'fetch', async (url, options) => {
    assert(['https://pinecone-fixture.invalid/vectors/upsert', 'https://pinecone-fixture.invalid/query',
      'http://127.0.0.1:5082/vectors/upsert', 'http://127.0.0.1:5082/query'].includes(String(url)));
    assert.equal(options.method, 'POST');
    calls.push({ url: String(url), body: JSON.parse(options.body), header_names: Object.keys(options.headers) });
    return { ok: true, status: 200, statusText: 'OK', text: async () => JSON.stringify({ fixture_response: true, matches: [] }) };
  });
  try {
    for (const key of Object.keys(process.env)) if (envKey(key)) delete process.env[key];
    fs.mkdirSync(path.join(state, 'external_memory/sources'), { recursive: true });
    fs.writeFileSync(path.join(state, 'external_memory/sources/public.md'), 'Explicitly selected public fixture source.\n');
    fs.writeFileSync(path.join(state, 'config.yaml'), 'updates:\n  enabled: false\n');
    Object.assign(process.env, { KNOWLEDGE_DISABLE_GIT_DISCOVERY: '1', KNOWLEDGE_UPDATE_DISABLE_ON_LAUNCH: '1',
      KNOWLEDGE_SYSTEM_ROOT: system, KNOWLEDGE_TARGET_ROOT: root, KNOWLEDGE_PROJECT_KNOWLEDGE_ROOT: state,
      KNOWLEDGE_STATE_ROOT: state, KNOWLEDGE_MODE: 'repo' });
    const main = require('../tools/memory-pinecone');
    const pc = require('../tools/external/pinecone-common');
    const configure = (values = cloud) => {
      for (const key of Object.keys(process.env)) if (/^PINECONE_/i.test(key) || key === 'KNOWLEDGE_MEMORY_PROVIDER_TEST_MODE') delete process.env[key];
      Object.assign(process.env, values);
    };
    const dispatch = async (flags, allowed, values = cloud) => {
      configure(values);
      for (const args of operations) {
        const before = calls.length, result = await main([...args, ...flags, '--json']);
        assert.equal(calls.length - before, allowed ? 1 : 0, `${args[0]} ${flags.join(' ')}`);
        assert.equal(result.source_of_truth, false); assert.equal(result.trust_effect, 'advisory_only');
        assert.equal(result.network_calls, allowed ? 'explicit_live_call' : 'not_run');
        if (allowed) assert.equal(result.status, 'ok');
        else { assert.equal(result.dry_run, true); assert.notEqual(result.persisted, true); }
      }
    };
    await run({ main, pc, configure, dispatch, calls });
    assert.deepEqual(forbidden, []);
  } finally {
    for (const [object, entries] of originals) for (const [key, value] of entries) object[key] = value;
    for (const key of Object.keys(process.env)) if (envKey(key)) delete process.env[key];
    Object.assign(process.env, savedEnv);
    for (const filename of Object.keys(require.cache)) if (!cacheBefore.has(filename) && filename.startsWith(system + path.sep)) delete require.cache[filename];
    removeTempDirStrict(root, { expectedIdentity: identity });
  }
}

test('Pinecone preview and health do not dispatch without both consent and configured mode', () => pineconeFixture(async f => {
  await f.dispatch([], false);
  await f.dispatch([], false, { PINECONE_MODE: 'local', PINECONE_HOST: 'http://127.0.0.1:5082' });
  for (const values of [{ ...cloud, PINECONE_MODE: 'disabled' },
    { PINECONE_MODE: 'cloud', PINECONE_HOST: cloud.PINECONE_HOST },
    { PINECONE_MODE: 'cloud', PINECONE_API_KEY: cloud.PINECONE_API_KEY }, {}]) {
    await f.dispatch(['--live'], false, values);
    f.configure(values);
    const before = f.calls.length, health = await f.main(['health', '--live', '--json']);
    assert.equal(f.calls.length, before); assert.equal(health.network_calls, 'not_run');
    assert.notEqual(health.runtime_health, 'healthy');
  }
}));

test('Pinecone accepts exact affirmative consent scalars for remember, recall and source sync', () => pineconeFixture(async f => {
  for (const flag of ['--live', '--yes-live-memory']) {
    await f.dispatch([flag], true);
    for (const value of ['true', '1', 'yes', 'y', 'on', ' TRUE ']) await f.dispatch([`${flag}=${value}`], true);
  }
  await f.dispatch(['--live', 'true'], true);
  await f.dispatch(['--live=true', '--dry-run=false'], true);
  await f.dispatch(['--live'], true, { PINECONE_MODE: 'local', PINECONE_HOST: 'http://127.0.0.1:5082' });
}));

test('Pinecone explicit negative consent scalars deny every operation, including test mode', () => pineconeFixture(async f => {
  for (const flag of ['--live', '--yes-live-memory']) {
    for (const value of ['false', '0', 'no', 'n', 'off', '', ' FALSE ']) {
      await f.dispatch([`${flag}=${value}`], false);
      await f.dispatch([`${flag}=${value}`], false, { ...cloud, KNOWLEDGE_MEMORY_PROVIDER_TEST_MODE: '1' });
    }
  }
  await f.dispatch(['--live', 'false'], false);
  await f.dispatch(['--live=false', '--yes-live-memory'], false);
  await f.dispatch(['--live', '--yes-live-memory=false'], false);
}));

test('Pinecone dry-run wins over either live flag and the test-mode opt-in', () => pineconeFixture(async f => {
  for (const dry of ['--dry-run', '--dry-run=true', '--dry-run=1', '--dry-run=yes', '--dry-run=y', '--dry-run=on', '--dry-run= TRUE ']) {
    await f.dispatch(['--live', dry], false);
    await f.dispatch(['--yes-live-memory=true', dry], false);
    await f.dispatch([dry], false, { ...cloud, KNOWLEDGE_MEMORY_PROVIDER_TEST_MODE: '1' });
  }
  for (const value of ['false', '0', 'no', 'n', 'off', '']) await f.dispatch(['--live=true', `--dry-run=${value}`], true);
  await f.dispatch(['--dry-run=false'], false);
}));

test('Pinecone environment opt-in remains exact and cannot replace required host, key or enabled mode', () => pineconeFixture(async f => {
  for (const value of ['false', '0', 'true', 'yes', 'on', ' 1 ', '']) {
    await f.dispatch([], false, { ...cloud, KNOWLEDGE_MEMORY_PROVIDER_TEST_MODE: value });
  }
  await f.dispatch([], true, { ...cloud, KNOWLEDGE_MEMORY_PROVIDER_TEST_MODE: '1' });
  for (const values of [{ ...cloud, PINECONE_MODE: 'disabled' },
    { PINECONE_MODE: 'cloud', PINECONE_HOST: cloud.PINECONE_HOST },
    { PINECONE_MODE: 'cloud', PINECONE_API_KEY: cloud.PINECONE_API_KEY }]) {
    await f.dispatch([], false, { ...values, KNOWLEDGE_MEMORY_PROVIDER_TEST_MODE: '1' });
  }
  f.configure({ PINECONE_LOCAL: 'false', PINECONE_HOST: cloud.PINECONE_HOST });
  assert.equal(f.pc.env().mode, 'disabled'); assert.equal(f.pc.env().configured, false);
}));

test('Pinecone rejects unknown consent and dry-run scalar values before transport', () => pineconeFixture(async f => {
  for (const flag of ['--live', '--yes-live-memory', '--dry-run']) {
    for (const value of ['2', 'maybe', 'truthy', 'null', '[]', '{}']) {
      f.configure({ ...cloud, KNOWLEDGE_MEMORY_PROVIDER_TEST_MODE: '1' });
      for (const args of operations) {
        const before = f.calls.length;
        await assert.rejects(() => f.main([...args, `${flag}=${value}`, '--json']), { code: 'pinecone_live_flag_invalid' });
        assert.equal(f.calls.length, before);
      }
    }
  }
}));
