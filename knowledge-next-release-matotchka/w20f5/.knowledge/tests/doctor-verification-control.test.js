'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');
const source = path.resolve(__dirname, '..');

if (process.argv[2] === '--fixture') {
  const root = process.argv[3], mode = process.argv[4], state = path.join(root, '.knowledge');
  fs.mkdirSync(state);
  fs.writeFileSync(path.join(state, 'config.yaml'), 'updates:\n  enabled: false\n');
  Object.assign(process.env, { KNOWLEDGE_MODE: 'repo', KNOWLEDGE_DISABLE_GIT_DISCOVERY: '1',
    KNOWLEDGE_SYSTEM_ROOT: source, KNOWLEDGE_TARGET_ROOT: root,
    KNOWLEDGE_PROJECT_KNOWLEDGE_ROOT: state, KNOWLEDGE_STATE_ROOT: state,
    KNOWLEDGE_AGENT_ID: 'doctor-verification-control-regression', CI: '1' });
  const doctor = require('../tools/doctor');
  const native = require('../tools/lib/repair-on-touch');
  const control = require('../tools/lib/verification-control');
  const context = { stateRoot: state, projectKnowledgeRoot: state, targetRoot: root, systemRoot: source };
  const taskScope = native.buildTaskScope({ task_id: 'operational-task', session_id: 'operational-session',
    selected_modules: ['unrelated'], changed_files: ['unrelated/file.js'] });
  // Let Doctor create its ordinary generated artifacts before comparing scores.
  doctor({ quiet: true, taskScope });
  doctor({ quiet: true, taskScope });
  const baseline = doctor({ quiet: true, taskScope });
  const active = path.join(state, 'maintenance/verification-control/active.json');
  if (['claimed', 'quarantine', 'terminal', 'dead-initiator'].includes(mode)) {
    const { owner } = control.beginAttempt(context, { request_sha256: 'a'.repeat(64) });
    if (mode === 'quarantine') {
      control.updateAttempt(context, owner, { type: 'stop', reason: 'failure' });
      control.updateAttempt(context, owner, { type: 'cleanup_started' });
      control.updateAttempt(context, owner, { type: 'cleanup_unconfirmed' });
    }
    if (mode === 'terminal') control.commitFinish(context, owner, { outcome: 'failed',
      cleanup_proof: { attempt_id: owner.attempt_id, generation: owner.generation, method: 'no_processes_started' } });
    if (mode === 'dead-initiator') {
      const value = JSON.parse(fs.readFileSync(active)); value.initiator.pid = 2147483647;
      fs.writeFileSync(active, JSON.stringify(value));
    }
  } else if (mode === 'corrupt' || mode === 'unsafe-directory') {
    fs.mkdirSync(path.dirname(active), { recursive: true });
    if (mode === 'corrupt') fs.writeFileSync(active, '{broken');
    else fs.mkdirSync(active);
  } else if (mode === 'registry-link') {
    const target = path.join(root, 'registry-target'); fs.mkdirSync(target);
    fs.mkdirSync(path.dirname(path.dirname(active)), { recursive: true });
    fs.symlinkSync(target, path.dirname(active), process.platform === 'win32' ? 'junction' : 'dir');
  }
  const before = fs.existsSync(active) && fs.lstatSync(active).isFile() ? fs.readFileSync(active) : null;
  // A status projection must never derive permission to clear state from PID death.
  const oldKill = process.kill; process.kill = () => { throw Error('Doctor must not probe PID liveness'); };
  let report;
  try { report = doctor({ quiet: true, taskScope }); } finally { process.kill = oldKill; }
  if (before) assert.deepEqual(fs.readFileSync(active), before, 'Doctor changed verification ownership');
  process.stdout.write(JSON.stringify({ baseline, report }));
} else {
  for (const mode of ['idle', 'claimed', 'quarantine', 'terminal', 'dead-initiator', 'corrupt', 'unsafe-directory', 'registry-link']) {
    test(`Doctor verification projection: ${mode}`, () => {
      const root = fs.mkdtempSync(path.join(os.tmpdir(), 'kdvc-'));
      try {
        const child = spawnSync(process.execPath, [__filename, '--fixture', root, mode], {
          encoding: 'utf8', timeout: 30000, windowsHide: true, maxBuffer: 16 * 1024 * 1024
        });
        assert.equal(child.status, 0, child.stderr); assert(!child.error, String(child.error));
        const { baseline, report } = JSON.parse(child.stdout);
        assert.equal(report.global.score, baseline.global.score, 'Operational claim is not trust debt');
        assert.deepEqual(report.findings, baseline.findings, 'Operational claim must not create repair findings');
        const blocked = !['idle', 'terminal'].includes(mode);
        assert.equal(report.operational_readiness.status, blocked ? 'blocked' : 'not_blocked');
        if (blocked) {
          assert.equal(report.task_readiness.status, 'needs_verification');
          assert.equal(report.task_readiness.content_status, baseline.task_readiness.status);
          assert(report.task_readiness.operational_blockers.includes(
            ['corrupt', 'unsafe-directory', 'registry-link'].includes(mode) ? 'verification_control_unavailable' : 'verification_resource_claimed'));
        } else assert.equal(report.task_readiness.status, baseline.task_readiness.status);
        if (mode === 'quarantine') assert.equal(report.verification_control.attempt.cleanup.status, 'unconfirmed');
        if (['corrupt', 'unsafe-directory', 'registry-link'].includes(mode)) assert.equal(report.verification_control.status, 'unavailable');
        assert.equal(report.verification_control.observation, 'persisted_snapshot_not_live_liveness');
      } finally {
        // Only this mkdtemp tree; no fixture contains links or product paths.
        assert(path.dirname(root) === os.tmpdir() && path.basename(root).startsWith('kdvc-'));
        const registry = path.join(root, '.knowledge/maintenance/verification-control');
        if (fs.existsSync(registry) && fs.lstatSync(registry).isSymbolicLink()) fs.unlinkSync(registry);
        fs.rmSync(root, { recursive: true, force: true });
      }
    });
  }
}
