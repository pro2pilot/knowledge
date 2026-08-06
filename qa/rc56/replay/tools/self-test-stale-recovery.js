#!/usr/bin/env node
'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const { acquireContainedLock, lockPaths } = require('./lib/contained-lock-manager');
const { LOCKS } = require('./lib/lock-policy');
const { canonicalOwnerText } = require('./lib/lock-owner-schema');
const { removeTempDirStrict } = require('./lib/strict-temp-cleanup');

function parseArgs(argv) { const args = { out: null }; for (let i = 0; i < argv.length; i += 1) { if (argv[i] === '--out') args.out = argv[++i] || null; else if (argv[i].startsWith('--out=')) args.out = argv[i].slice(6); } return args; }
function context(root) { return { stateRoot: root, projectKnowledgeRoot: root, systemRoot: root, agentId: 'stale-recovery-self-test' }; }
function request(root, lockName = 'doctor', rootKind = 'state', extra = {}) { const resolved = context(root); return { context: resolved, rootKind, rootPath: root, lockName, purpose: LOCKS[lockName].purpose, timeoutMs: 25, staleMs: 10, ...extra }; }
function currentOwner(lockName, extra = {}) { const now = new Date().toISOString(); return { schema_version: 'knowledge-lock-owner.v1', lock_id: '123e4567-e89b-42d3-a456-426614174000', lock_name: lockName, purpose: LOCKS[lockName].purpose, pid: 2147483647, hostname: os.hostname(), agent_id: null, workspace_id: null, process_started_at: now, acquired_at: now, nonce: 'a'.repeat(64), ...extra }; }
function legacyOwner(extra = {}) { return { lock_id: 'legacy-stale', pid: 2147483647, hostname: os.hostname(), started_at: new Date().toISOString(), ...extra }; }
function age(target, milliseconds) { const old = new Date(Date.now() - milliseconds); fs.utimesSync(target, old, old); }
function seedCurrent(root, lockName, options = {}) { const paths = lockPaths(request(root, lockName, options.rootKind || 'state', options.resourceId ? { resourceId: options.resourceId } : {})); fs.mkdirSync(paths.lockDir, { recursive: true }); fs.writeFileSync(path.join(paths.lockDir, 'owner.json'), options.text || canonicalOwnerText(currentOwner(lockName, options.owner || {})), 'utf8'); age(paths.lockDir, options.ageMs || 130000); return paths; }
function seedLegacy(root, options = {}) { const legacy = path.join(root, '.lock'); fs.mkdirSync(legacy, { recursive: true }); fs.writeFileSync(path.join(legacy, 'owner.json'), JSON.stringify(legacyOwner(options.owner || {})), 'utf8'); age(legacy, options.ageMs || 130000); return legacy; }
function caseResult(results, id, execute) { try { const actual = execute(); results.push({ id, expected: { recovered: true }, actual, pass: actual.pass === true }); } catch (error) { results.push({ id, expected: { recovered: true }, actual: { error_code: error.code || null, message: error.message }, pass: false }); } }

function main() {
  const args = parseArgs(process.argv.slice(2));
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'knowledge-stale-recovery-'));
  const results = [];
  const root = (id) => { const value = path.join(temp, id); fs.mkdirSync(value, { recursive: true }); return value; };
  try {
    caseResult(results, 'current_local_stale_recovered', () => { const r = root('one'); const paths = seedCurrent(r, 'doctor'); const handle = acquireContainedLock(request(r)); handle.release(); return { lock_present: fs.existsSync(paths.lockDir), pass: !fs.existsSync(paths.lockDir) }; });
    caseResult(results, 'legacy_local_stale_recovered', () => { const r = root('two'); const legacy = seedLegacy(r); const handle = acquireContainedLock(request(r)); handle.release(); return { legacy_present: fs.existsSync(legacy), pass: !fs.existsSync(legacy) }; });
    caseResult(results, 'current_remote_stale_recovered', () => { const r = root('three'); const paths = seedCurrent(r, 'doctor', { owner: { hostname: 'remote-host' }, ageMs: 172800000 }); const handle = acquireContainedLock(request(r)); handle.release(); return { lock_present: fs.existsSync(paths.lockDir), pass: !fs.existsSync(paths.lockDir) }; });
    caseResult(results, 'legacy_remote_stale_recovered', () => { const r = root('four'); const legacy = seedLegacy(r, { owner: { hostname: 'remote-host' }, ageMs: 172800000 }); const handle = acquireContainedLock(request(r)); handle.release(); return { legacy_present: fs.existsSync(legacy), pass: !fs.existsSync(legacy) }; });
    caseResult(results, 'current_active_not_recovered', () => { const r = root('five'); const paths = seedCurrent(r, 'doctor', { owner: { pid: process.pid }, ageMs: 130000 }); let error = null; try { acquireContainedLock(request(r)); } catch (caught) { error = caught; } return { error_code: error?.code || null, lock_present: fs.existsSync(paths.lockDir), pass: error?.code === 'lock_timeout' && fs.existsSync(paths.lockDir) }; });
    caseResult(results, 'legacy_active_not_recovered', () => { const r = root('six'); const legacy = seedLegacy(r, { owner: { pid: process.pid }, ageMs: 130000 }); let error = null; try { acquireContainedLock(request(r)); } catch (caught) { error = caught; } return { error_code: error?.code || null, legacy_present: fs.existsSync(legacy), pass: error?.code === 'lock_timeout' && fs.existsSync(legacy) }; });
    caseResult(results, 'malformed_current_never_recovered', () => { const r = root('seven'); const paths = seedCurrent(r, 'doctor', { text: '{malformed' }); let error = null; try { acquireContainedLock(request(r)); } catch (caught) { error = caught; } return { error_code: error?.code || null, lock_present: fs.existsSync(paths.lockDir), pass: error?.code === 'lock_owner_invalid' && fs.existsSync(paths.lockDir) }; });
    caseResult(results, 'hardlinked_current_never_recovered', () => { const r = root('eight'); const paths = lockPaths(request(r)); const external = path.join(temp, 'eight-owner'); fs.mkdirSync(paths.lockDir, { recursive: true }); fs.writeFileSync(external, canonicalOwnerText(currentOwner('doctor')), 'utf8'); fs.linkSync(external, path.join(paths.lockDir, 'owner.json')); age(paths.lockDir, 130000); let error = null; try { acquireContainedLock(request(r)); } catch (caught) { error = caught; } return { error_code: error?.code || null, lock_present: fs.existsSync(paths.lockDir), pass: error?.code === 'lock_owner_hardlinked' && fs.existsSync(paths.lockDir) }; });
    caseResult(results, 'project_current_stale_recovered', () => { const r = root('nine'); const paths = seedCurrent(r, 'apply-template', { rootKind: 'project' }); const handle = acquireContainedLock(request(r, 'apply-template', 'project')); handle.release(); return { lock_present: fs.existsSync(paths.lockDir), pass: !fs.existsSync(paths.lockDir) }; });
    caseResult(results, 'legacy_upgrade_recovered', () => { const r = root('ten'); const legacy = seedLegacy(r); const handle = acquireContainedLock(request(r)); handle.release(); return { legacy_present: fs.existsSync(legacy), pass: !fs.existsSync(legacy) }; });
    caseResult(results, 'stale_recovery_preserves_lock_layout', () => { const r = root('eleven'); seedCurrent(r, 'doctor'); const handle = acquireContainedLock(request(r)); handle.release(); const version = path.join(r, 'locks', 'v1'); return { version_root_present: fs.existsSync(version), pass: fs.existsSync(version) }; });
    const report = { schema_version: 'knowledge-stale-recovery-self-test.v1', generated_at: new Date().toISOString(), checks_total: results.length, passed: results.filter((item) => item.pass).length, failed: results.filter((item) => !item.pass).length, status: results.every((item) => item.pass) ? 'pass' : 'fail', results };
    const text = `${JSON.stringify(report, null, 2)}\n`; if (args.out) { fs.mkdirSync(path.dirname(path.resolve(args.out)), { recursive: true }); fs.writeFileSync(path.resolve(args.out), text, 'utf8'); } process.stdout.write(text); if (report.failed) process.exitCode = 1;
  } finally { removeTempDirStrict(temp); }
}
if (require.main === module) main();
module.exports = { main };
