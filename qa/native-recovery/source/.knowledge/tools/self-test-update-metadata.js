#!/usr/bin/env node
'use strict';
const assert = require('assert/strict');
const fs = require('fs');
const path = require('path');
const os = require('os');
const { spawnSync } = require('child_process');
const root = fs.mkdtempSync(path.join(os.tmpdir(), 'knowledge-update-metadata-'));
const fixture = path.join(root, '.knowledge');
const checks = [];
const check = async (name, fn) => { await fn(); checks.push(name); };
const write = (file, value) => { fs.mkdirSync(path.dirname(file), { recursive: true }); fs.writeFileSync(file, typeof value === 'string' ? value : JSON.stringify(value)); };
const originalFetch = global.fetch;
const oldMock = process.env.KNOWLEDGE_UPDATE_MOCK_LATEST;
async function main() {
  try {
    delete process.env.KNOWLEDGE_UPDATE_MOCK_LATEST;
    for (const rel of ['tools/check-updates.js', 'tools/lib/system-version.js', 'tools/lib/json-store.js', 'tools/lib/strict-temp-cleanup.js', 'package.json']) {
      const dest = path.join(fixture, rel); fs.mkdirSync(path.dirname(dest), { recursive: true }); fs.copyFileSync(path.join(__dirname, '..', rel), dest);
    }
    write(path.join(fixture, 'config.yaml'), 'updates:\n  enabled: false\n  interval_days: invalid\n  timeout_ms: -1\n');
    const updater = require(path.join(fixture, 'tools/check-updates.js'));
    const config = updater.getConfig();
    await check('malformed numeric configuration uses finite defaults', () => { assert.equal(config.interval_days, 7); assert.equal(config.timeout_ms, 5000); });
    await check('disabled auto-check never invokes the network function', async () => { global.fetch = () => { throw new Error('Network must not be reached'); }; const result = await updater(['--auto', '--quiet']); assert.equal(result.status, 'disabled'); });
    await check('null cached status recovers as never_checked', () => { write(path.join(fixture, 'maintenance/update_status.json'), 'null'); assert.equal(updater.readStatus().status, 'never_checked'); assert.equal(updater.isDue({ enabled: true, interval_days: 7 }, updater.readStatus()), true); });
    await check('offline fetch failure remains advisory check_failed', async () => { global.fetch = async () => { throw new Error('fixture offline'); }; const result = await updater.checkNow(config); assert.equal(result.status, 'check_failed'); assert.equal(result.error, 'fixture offline'); });
    for (const [name, data] of [['null release', null], ['empty release', {}], ['malformed tag', { tag_name: 'banana' }], ['draft release', { tag_name: '99.0.0', draft: true }]]) {
      await check(`${name} cannot claim up_to_date`, async () => { global.fetch = async () => ({ ok: true, text: async () => JSON.stringify(data) }); assert.equal((await updater.checkNow(config)).status, 'check_failed'); });
    }
    await check('release HTTP failure is check_failed', async () => { global.fetch = async () => ({ ok: false, status: 503, statusText: 'Fixture unavailable', text: async () => '{}' }); assert.equal((await updater.checkNow(config)).status, 'check_failed'); });
    await check('newer valid release is advisory and selects its exact asset', async () => { global.fetch = async () => ({ ok: true, text: async () => JSON.stringify({ tag_name: 'v99.0.0', assets: [null, { name: 'knowledge-v99.0.0.zip', browser_download_url: 'mock://asset' }] }) }); const result = await updater.checkNow(config); assert.equal(result.status, 'update_available'); assert.equal(result.auto_update, false); assert.equal(result.asset_name, 'knowledge-v99.0.0.zip'); });
    await check('prerelease ordering distinguishes stable and numeric identifiers', () => { assert.equal(updater.compareVersions('3.4.3-rc.1', '3.4.3'), -1); assert.equal(updater.compareVersions('3.4.3-rc.2', '3.4.3-rc.10'), -1); assert.equal(updater.compareVersions('3.4.3+build.1', '3.4.3+build.2'), 0); assert.throws(() => updater.compareVersions('unknown', '3.4.3')); });
    await check('invalid installed package metadata cannot claim current release', async () => { write(path.join(fixture, 'package.json'), 'null'); assert.equal((await updater.checkNow(config)).status, 'check_failed'); });
    fs.copyFileSync(path.join(__dirname, '..', 'package.json'), path.join(fixture, 'package.json'));
    const cli = (args) => { const result = spawnSync(process.execPath, [path.join(fixture, 'tools/check-updates.js'), ...args, '--json'], { cwd: root, encoding: 'utf8', env: { ...process.env, KNOWLEDGE_UPDATE_MOCK_LATEST: '' } }); assert(result.stdout, result.stderr || result.error?.message); return { exit: result.status, body: JSON.parse(result.stdout) }; };
    await check('conflicting enable and disable options are rejected without write', () => { const before = fs.readFileSync(path.join(fixture, 'config.yaml')); assert.equal(cli(['--enable', '--disable']).exit, 1); assert.deepEqual(fs.readFileSync(path.join(fixture, 'config.yaml')), before); });
    await check('oversized update interval is rejected', () => assert.equal(cli(['--interval=999999999999999999999']).exit, 1));
    if (process.platform !== 'win32') await check('configuration symlink cannot write outside the installation', () => { const outside = path.join(root, 'outside.yaml'); write(outside, 'untouched'); fs.rmSync(path.join(fixture, 'config.yaml')); fs.symlinkSync(outside, path.join(fixture, 'config.yaml')); assert.equal(cli(['--enable']).exit, 1); assert.equal(fs.readFileSync(outside, 'utf8'), 'untouched'); });
    console.log(JSON.stringify({ status: 'pass', checks_total: checks.length, checks, network_used: false }, null, 2));
  } finally {
    global.fetch = originalFetch;
    if (oldMock === undefined) delete process.env.KNOWLEDGE_UPDATE_MOCK_LATEST; else process.env.KNOWLEDGE_UPDATE_MOCK_LATEST = oldMock;
    fs.rmSync(root, { recursive: true, force: true });
  }
}
main().catch((error) => { console.error(error.stack || error.message); process.exitCode = 1; });
