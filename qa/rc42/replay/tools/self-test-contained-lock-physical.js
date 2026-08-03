#!/usr/bin/env node
'use strict';

const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');
const { validate, readZipEntries } = require('./validate-release-artifact');
const { removeTempDirStrict } = require('./lib/strict-temp-cleanup');

const SECRET = 'RC39_PHYSICAL_LOCK_SECRET_MUST_NOT_LEAK';

function args(argv) {
  const out = { zip: null, out: null };
  for (let i = 0; i < argv.length; i += 1) {
    if (argv[i] === '--zip') out.zip = argv[++i];
    else if (argv[i].startsWith('--zip=')) out.zip = argv[i].slice(6);
    else if (argv[i] === '--out') out.out = argv[++i];
    else if (argv[i].startsWith('--out=')) out.out = argv[i].slice(6);
  }
  if (!out.zip) throw new Error('--zip=<physical candidate ZIP> is required');
  return out;
}

function extract(zipPath, root) {
  const checked = validate(zipPath);
  if (checked.status !== 'ok') throw new Error('candidate validation failed');
  const zip = readZipEntries(zipPath);
  for (const entry of zip.entries) {
    if (entry.name.endsWith('/')) continue;
    const rel = entry.name.replace(/\\/g, '/');
    if (!rel || rel.startsWith('/') || rel.split('/').includes('..')) throw new Error(`unsafe ZIP entry: ${entry.name}`);
    const target = path.resolve(root, ...rel.split('/'));
    if (!target.startsWith(`${path.resolve(root)}${path.sep}`)) throw new Error(`escaping ZIP entry: ${entry.name}`);
    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.writeFileSync(target, entry.body);
  }
  return checked;
}

function sleep(ms) { Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms); }
function sha(file) { return crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex'); }
function main() {
  const parsed = args(process.argv.slice(2));
  const zipPath = path.resolve(parsed.zip);
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'knowledge-rc39-physical-'));
  const extracted = path.join(temp, 'candidate');
  const fixtures = path.join(temp, 'fixtures');
  const results = [];
  let validation;
  try {
    validation = extract(zipPath, extracted);
    const knowledgeRoot = path.join(extracted, '.knowledge');
    const managerPath = path.join(knowledgeRoot, 'tools', 'lib', 'contained-lock-manager.js');
    const policyPath = path.join(knowledgeRoot, 'tools', 'lib', 'lock-policy.js');
    const manager = require(managerPath);
    const { LOCKS } = require(policyPath);
    const { canonicalOwnerText } = require(path.join(knowledgeRoot, 'tools', 'lib', 'lock-owner-schema.js'));

    function root(id) { const value = path.join(fixtures, id); fs.mkdirSync(value, { recursive: true }); return value; }
    function request(rootPath, lockName = 'doctor', extra = {}) {
      return { context: { stateRoot: rootPath }, rootKind: 'state', rootPath, lockName,
        purpose: LOCKS[lockName].purpose, timeoutMs: 20, staleMs: 1, ...extra };
    }
    function owner(lockName = 'doctor', extra = {}) {
      const now = new Date().toISOString();
      return { schema_version: 'knowledge-lock-owner.v1', lock_id: '123e4567-e89b-42d3-a456-426614174000',
        lock_name: lockName, purpose: LOCKS[lockName].purpose, pid: process.pid, hostname: os.hostname(),
        agent_id: null, workspace_id: null, process_started_at: now, acquired_at: now, nonce: 'a'.repeat(64), ...extra };
    }
    function seed(rootPath, text, ageMs = 0, lockName = 'doctor') {
      const paths = manager.lockPaths(request(rootPath, lockName));
      fs.mkdirSync(paths.lockDir, { recursive: true });
      fs.writeFileSync(path.join(paths.lockDir, 'owner.json'), text, 'utf8');
      if (ageMs) { const old = new Date(Date.now() - ageMs); fs.utimesSync(paths.lockDir, old, old); }
      return paths;
    }
    function thrown(fn) { try { fn(); return null; } catch (error) { return error; } }
    function run(id, fn) {
      const sentinel = path.join(temp, `${id}-external-sentinel.txt`);
      fs.writeFileSync(sentinel, SECRET, 'utf8');
      const before = sha(sentinel);
      try {
        const detail = fn(sentinel) || {};
        const text = JSON.stringify(detail);
        const secretLeaked = text.includes(SECRET);
        const externalChanged = sha(sentinel) !== before;
        results.push({ id, status: detail.status || 'pass', pass: detail.status === 'unsupported' ? null : !secretLeaked && !externalChanged,
          external_read_detected: secretLeaked, external_write_detected: externalChanged, secret_leaked: secretLeaked,
          exit_code: detail.exit_code ?? 0, final_lock_state: detail.final_lock_state || null,
          ...(detail.status === 'unsupported' ? { limitation: detail.limitation } : {}),
          ...(detail.error_code ? { error_code: detail.error_code } : {}) });
      } catch (error) {
        results.push({ id, status: 'fail', pass: false, external_read_detected: false,
          external_write_detected: sha(sentinel) !== before, secret_leaked: String(error.message).includes(SECRET),
          exit_code: 1, final_lock_state: null, error_code: error.code || null, error: error.message.replaceAll(SECRET, '[REDACTED]') });
      }
    }
    function unsafe(id, setup, expectedCodes) {
      run(id, (sentinel) => {
        const r = root(id); const paths = manager.lockPaths(request(r));
        setup({ r, paths, sentinel });
        const error = thrown(() => manager.acquireContainedLock(request(r)));
        if (!error || !expectedCodes.includes(error.code)) throw new Error(`expected ${expectedCodes.join('/')}, got ${error?.code || 'success'}`);
        if (String(error.message).includes(SECRET)) throw new Error('secret leaked');
        return { exit_code: 1, error_code: error.code, final_lock_state: fs.existsSync(paths.lockDir) ? 'preserved' : 'absent' };
      });
    }
    function symlinkCase(id, targetPart, type) {
      unsafe(id, ({ r, paths, sentinel }) => {
        const external = path.join(temp, `${id}-external`); fs.mkdirSync(external, { recursive: true });
        fs.writeFileSync(path.join(external, 'owner.json'), SECRET, 'utf8');
        const target = targetPart === 'layout' ? paths.layoutRoot : paths.lockDir;
        fs.mkdirSync(path.dirname(target), { recursive: true });
        fs.symlinkSync(external, target, type);
        fs.writeFileSync(sentinel, SECRET, 'utf8');
      }, ['unsafe_lock_parent', 'unsafe_lock_path']);
    }
    function ownerSymlink(id) {
      run(id, (sentinel) => {
        const r = root(id); const paths = manager.lockPaths(request(r));
        fs.mkdirSync(paths.lockDir, { recursive: true });
        const external = path.join(temp, `${id}-owner.json`); fs.writeFileSync(external, canonicalOwnerText(owner()), 'utf8');
        try { fs.symlinkSync(external, path.join(paths.lockDir, 'owner.json'), 'file'); }
        catch (error) { return { status: 'unsupported', limitation: { code: error.code || null, reason: 'file_symlink_privilege_unavailable' } }; }
        const error = thrown(() => manager.acquireContainedLock(request(r)));
        if (error?.code !== 'unsafe_lock_owner') throw new Error(`expected unsafe_lock_owner, got ${error?.code || 'success'}`);
        if (String(error.message).includes(SECRET)) throw new Error('secret leaked');
        fs.writeFileSync(sentinel, SECRET, 'utf8');
        return { exit_code: 1, error_code: error.code, final_lock_state: 'preserved' };
      });
    }
    function stale(id) {
      run(id, () => {
        const r = root(id); const paths = seed(r, canonicalOwnerText(owner('doctor', { pid: 2147483647 })), 60_000);
        const handle = manager.acquireContainedLock(request(r)); handle.release();
        if (fs.existsSync(paths.lockDir)) throw new Error('stale lock remains');
        return { final_lock_state: 'released' };
      });
    }
    function active(id) {
      run(id, () => {
        const r = root(id); const paths = seed(r, canonicalOwnerText(owner()), 60_000);
        const error = thrown(() => manager.acquireContainedLock(request(r)));
        if (error?.code !== 'lock_timeout' || String(error.message).includes(SECRET)) throw new Error(`active lock result=${error?.code || 'success'}`);
        return { exit_code: 1, error_code: error.code, final_lock_state: fs.existsSync(paths.lockDir) ? 'preserved' : 'absent' };
      });
    }
    function concurrency(id, holdMs = 180) {
      run(id, () => {
        const r = root(id);
        const worker = [
          "const {acquireContainedLock}=require(process.argv[1]);const {LOCKS}=require(process.argv[2]);const root=process.argv[3],hold=Number(process.argv[4]);",
          "const request={context:{stateRoot:root},rootKind:'state',rootPath:root,lockName:'doctor',purpose:LOCKS.doctor.purpose,timeoutMs:5000,staleMs:60000};",
          "const start=Date.now(),h=acquireContainedLock(request);const waited=Date.now()-start;Atomics.wait(new Int32Array(new SharedArrayBuffer(4)),0,0,hold);h.release();process.stdout.write(String(waited));"
        ].join('');
        const orchestrator = [
          "const {spawn}=require('child_process');const worker=process.argv[1],manager=process.argv[2],policy=process.argv[3],root=process.argv[4],hold=process.argv[5];",
          "const one=(delay)=>new Promise((resolve)=>setTimeout(()=>{const c=spawn(process.execPath,['-e',worker,manager,policy,root,hold],{windowsHide:true});let out='',err='';c.stdout.on('data',(v)=>out+=v);c.stderr.on('data',(v)=>err+=v);c.on('close',(code)=>resolve({code,out,err}));},delay));",
          "Promise.all([one(0),one(30)]).then((v)=>{process.stdout.write(JSON.stringify(v));if(v.some((x)=>x.code!==0))process.exitCode=1;});"
        ].join('');
        const proc = spawnSync(process.execPath, ['-e', orchestrator, worker, managerPath, policyPath, r, String(holdMs)], { encoding: 'utf8', timeout: 30000, windowsHide: true });
        if (proc.status !== 0) throw new Error(`concurrency children failed: ${proc.stderr}`);
        const children = JSON.parse(proc.stdout); const waits = children.map((item) => Number(item.out));
        if (!waits.some((value) => value >= 80)) throw new Error(`lock did not serialize: ${waits.join(',')}`);
        return { final_lock_state: fs.existsSync(manager.lockPaths(request(r)).lockDir) ? 'present' : 'released' };
      });
    }

    if (process.platform === 'win32') {
      symlinkCase('win01_lock_directory_junction', 'lock', 'junction');
      symlinkCase('win02_nested_parent_junction', 'layout', 'junction');
      ownerSymlink('win03_owner_file_symlink');
      ownerSymlink('win04_owner_reparse_point');
      run('win05_external_drive_target', () => ({ status: 'unsupported', limitation: { reason: 'no_second_physical_drive_fixture_available' } }));
      run('win06_unc_target', () => ({ status: 'unsupported', limitation: { reason: 'no_test_UNC_share_available' } }));
      symlinkCase('win07_team_state_root_junction', 'lock', 'junction');
      active('win08_persistent_active_lock');
      stale('win09_stale_dead_owner_recovery');
      concurrency('win10_concurrent_serialization');
      concurrency('win11_transient_retry_behavior', 220);
      unsafe('win12_secret_field_not_echoed', ({ r }) => seed(r, `${JSON.stringify({ ...owner(), secret: SECRET }, null, 2)}\n`, 60_000), ['lock_owner_invalid']);
    } else {
      symlinkCase('linux01_lock_directory_symlink', 'lock', 'dir');
      symlinkCase('linux02_nested_lock_parent_symlink', 'layout', 'dir');
      ownerSymlink('linux03_owner_file_symlink');
      unsafe('linux04_owner_hardlink', ({ r, paths }) => { fs.mkdirSync(paths.lockDir, { recursive: true }); const outside = path.join(temp, 'hardlink-owner.json'); fs.writeFileSync(outside, canonicalOwnerText(owner()), 'utf8'); fs.linkSync(outside, path.join(paths.lockDir, 'owner.json')); }, ['lock_owner_hardlinked']);
      unsafe('linux05_dangling_lock_symlink', ({ paths }) => { fs.mkdirSync(path.dirname(paths.lockDir), { recursive: true }); fs.symlinkSync(path.join(temp, 'missing-target'), paths.lockDir, 'dir'); }, ['unsafe_lock_path']);
      unsafe('linux06_lock_parent_regular_file', ({ paths }) => { fs.writeFileSync(paths.layoutRoot, 'file', 'utf8'); }, ['unsafe_lock_parent']);
      unsafe('linux07_malformed_owner_json', ({ r }) => seed(r, `{malformed-${SECRET}`, 60_000), ['lock_owner_invalid']);
      unsafe('linux08_oversized_owner_json', ({ r }) => seed(r, 'x'.repeat(4097), 60_000), ['lock_owner_oversized']);
      unsafe('linux09_secret_unknown_field', ({ r }) => seed(r, `${JSON.stringify({ ...owner(), secret: SECRET }, null, 2)}\n`, 60_000), ['lock_owner_invalid']);
      stale('linux10_stale_dead_owner');
      active('linux11_active_owner_timeout');
      concurrency('linux12_concurrent_processes');
      run('linux13_owner_replacement', () => { const r = root('linux13_owner_replacement'); const h = manager.acquireContainedLock(request(r)); const file = path.join(h.path, 'owner.json'); const value = JSON.parse(fs.readFileSync(file, 'utf8')); value.nonce = 'b'.repeat(64); fs.writeFileSync(file, canonicalOwnerText(value)); const error = thrown(() => h.release()); if (error?.code !== 'lock_ownership_changed') throw new Error('replacement was not detected'); return { exit_code: 1, error_code: error.code, final_lock_state: 'replacement_preserved' }; });
      run('linux14_lock_directory_replacement', () => { const r = root('linux14_lock_directory_replacement'); const h = manager.acquireContainedLock(request(r)); const old = `${h.path}.old`; fs.renameSync(h.path, old); fs.mkdirSync(h.path); fs.writeFileSync(path.join(h.path, 'owner.json'), canonicalOwnerText(owner('doctor', { nonce: 'c'.repeat(64) }))); const error = thrown(() => h.release()); if (error?.code !== 'lock_ownership_changed') throw new Error('directory replacement was not detected'); return { exit_code: 1, error_code: error.code, final_lock_state: 'replacement_preserved' }; });
      run('linux15_team_external_state_root', () => { const r = root('external-team-state'); const req = request(r, 'team-flow'); const h = manager.acquireContainedLock(req); h.release(); return { final_lock_state: 'released' }; });
    }

    const failures = results.filter((item) => item.status === 'fail' || item.pass === false);
    const unsupported = results.filter((item) => item.status === 'unsupported');
    const report = { schema_version: 'knowledge-contained-lock-physical.v1', generated_at: new Date().toISOString(),
      platform: process.platform, node: process.version, candidate: { path: zipPath, sha256: sha(zipPath), validation_status: validation.status },
      checks_total: results.length, passed_total: results.filter((item) => item.pass === true).length,
      unsupported_total: unsupported.length, failed_total: failures.length,
      status: failures.length ? 'FAIL' : 'PASS', limitations: unsupported.map((item) => ({ id: item.id, ...item.limitation })), results };
    const text = `${JSON.stringify(report, null, 2)}\n`;
    if (parsed.out) { fs.mkdirSync(path.dirname(path.resolve(parsed.out)), { recursive: true }); fs.writeFileSync(path.resolve(parsed.out), text); }
    process.stdout.write(text);
    if (failures.length) process.exitCode = 1;
    return report;
  } finally {
    removeTempDirStrict(temp);
  }
}

if (require.main === module) main();
module.exports = { main };
