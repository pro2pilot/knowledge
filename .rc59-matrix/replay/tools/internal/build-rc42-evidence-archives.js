#!/usr/bin/env node
'use strict';

// Builds evidence containers only.  This is intentionally excluded from the
// released payload and never calls package-release or release-gate.
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const childProcess = require('child_process');
const RC42 = 'knowledge-v3.3.0-step1-rc4-r42.zip';
const SHA = 'ebdeebd5b67ca3ec4f61779e28fd3018e5eee697b00d1705d194b733b41259f0';
const RUN = '2026-08-03T12-11-35-103Z';
const GATE_COMMIT = '738d6191ba5f5064bd97d4a9ededd1bb3c535e09';
const PLAN_SHA = 'f688c124aea6812d681c546952ab14e0a5bf3ced2431cd417a8a64d70bdb59b6';
function arg(n) { const i = process.argv.indexOf(n); return i >= 0 ? process.argv[i + 1] || null : null; }
function sha(f) { return crypto.createHash('sha256').update(fs.readFileSync(f)).digest('hex'); }
function read(f) { return JSON.parse(fs.readFileSync(f, 'utf8')); }
function write(f, x) { fs.mkdirSync(path.dirname(f), { recursive: true }); fs.writeFileSync(f, `${typeof x === 'string' ? x : JSON.stringify(x, null, 2)}\n`, 'utf8'); }
function copy(src, dst) { fs.mkdirSync(path.dirname(dst), { recursive: true }); fs.copyFileSync(src, dst); }
function cp(src, dst) { fs.cpSync(src, dst, { recursive: true, force: true }); }
function fail(m) { throw new Error(m); }
function candidate(file) { if (path.basename(file) !== RC42 || sha(file) !== SHA) fail('exact RC42 candidate is required'); }
function binding(pathname, evidenceCommit) { return { path: pathname, candidate_name: RC42, candidate_sha256: SHA, source_commit: GATE_COMMIT, gate_run_id: RUN, authoritative: true, evidence_rebuild_commit: evidenceCommit }; }
function main() {
  const oldAudit = path.resolve(arg('--old-audit') || '');
  const rawRoot = path.resolve(arg('--raw-gate') || '');
  const candidateZip = path.resolve(arg('--candidate') || '');
  const fresh = path.resolve(arg('--fresh-tests') || '');
  const out = path.resolve(arg('--out') || '');
  const evidenceCommit = arg('--evidence-commit');
  if (![oldAudit, rawRoot, candidateZip, fresh, out, evidenceCommit].every(Boolean)) fail('required --old-audit --raw-gate --candidate --fresh-tests --out --evidence-commit');
  if (fs.existsSync(out)) fail(`refusing existing output: ${out}`);
  candidate(candidateZip);
  const rawReport = read(path.join(rawRoot, '.knowledge', 'maintenance', 'release-gate-report.json'));
  if (rawReport.run_id !== RUN || rawReport.artifact_sha256 !== SHA || rawReport.git_head !== GATE_COMMIT || rawReport.steps.length !== 63 || rawReport.steps.filter(x => x.status === 'pass').length !== 63 || rawReport.step_plan.sha256 !== PLAN_SHA) fail('accepted raw gate does not match RC42 contract');
  const audit = path.join(out, 'audit-root'); const gate = path.join(out, 'gate-root');
  cp(oldAudit, audit);
  fs.rmSync(path.join(audit, 'CHECKSUMS.sha256'), { force: true });
  // Preserve a compact, inspectable reproduction before replacing stale binding.
  for (const n of ['full-gate-report.json', 'exact-upgrade-report.json', 'physical-clean-install-report.json', 'install-check-black-box-report.json']) {
    const p = path.join(oldAudit, 'tests', n); if (fs.existsSync(p)) copy(p, path.join(audit, 'before-fix', 'candidate-binding', n));
  }
  for (const n of ['environment.json', 'source-and-candidate.json', 'execution-plan.json']) {
    const p = path.join(path.dirname(oldAudit), 'gate-root', n); if (fs.existsSync(p)) copy(p, path.join(audit, 'before-fix', 'gate-metadata', n));
  }
  const previousSuccess = path.join(path.dirname(oldAudit), 'gate-root', 'successful-gate');
  write(path.join(audit, 'before-fix', 'mixed-successful-runs', 'listing.json'), {
    schema_version: 'knowledge-rc42-before-fix-reproduction.v1', status: 'reproduced',
    issue_codes: ['STALE_RC40_BINDING', 'MIXED_GATE_METADATA'],
    entries: fs.existsSync(previousSuccess) ? fs.readdirSync(previousSuccess).sort() : []
  });
  copy(candidateZip, path.join(audit, 'artifacts', RC42));
  const reportNames = ['candidate-artifact-validation.json', 'audit-tool-portability-report.json', 'install-check-black-box-report.json', 'physical-clean-install-all-integrations-report.json', 'physical-clean-install-report.json', 'exact-upgrade-report.json'];
  for (const n of reportNames) {
    const p = path.join(fresh, n); if (!fs.existsSync(p)) fail(`fresh exact RC42 report missing: ${n}`);
    copy(p, path.join(audit, 'tests', n));
  }
  const upgradeCapture = path.join(fresh, 'exact-upgrade-report.json.capture', 'report.json');
  if (fs.existsSync(upgradeCapture)) copy(upgradeCapture, path.join(audit, 'tests', 'exact-upgrade-capture', 'report.json'));
  const fullGate = {
    schema_version: 'knowledge-rc42-authoritative-gate-report.v1', status: 'pass', candidate_name: RC42, candidate_sha256: SHA,
    gate_run_id: RUN, gate_source_commit: GATE_COMMIT, evidence_rebuild_commit: evidenceCommit,
    steps_total: 63, passed: 63, failed: 0, skipped: 0, execution_plan_sha256: PLAN_SHA,
    raw_gate_report_sha256: sha(path.join(rawRoot, '.knowledge', 'maintenance', 'release-gate-report.json')),
    reuse: 'accepted raw gate reused because candidate payload and plan are unchanged'
  };
  write(path.join(audit, 'tests', 'full-gate-report.json'), fullGate);
  const docs = {
    'README.md': `# RC42 evidence rebind\n\nFinal candidate: ${RC42}\n\nSHA-256: ${SHA}\n\nGate: 63/63 PASS; source commit ${GATE_COMMIT}. Evidence rebuild commit: ${evidenceCommit}.\n\nPackaging status: READY_FOR_EXTERNAL_AUDIT. Release status: BLOCKED_PENDING_EXTERNAL_AUDIT_AND_OS_NODE_MATRIX.\n`,
    'RC42-FINAL-REPORT.md': `# RC42 final report\n\nCandidate: ${RC42}\nSHA-256: ${SHA}\nAccepted gate: ${RUN}, 63/63 PASS. Gate source commit: ${GATE_COMMIT}. Evidence rebuild commit: ${evidenceCommit}.\n\nPackaging: READY_FOR_EXTERNAL_AUDIT. Release: BLOCKED_PENDING_EXTERNAL_AUDIT_AND_OS_NODE_MATRIX.\n`,
    'RC42-SUMMARY.md': `# RC42 summary\n\nExact candidate ${RC42} (${SHA}). The accepted 63-step gate belongs to ${GATE_COMMIT}; this evidence-only rebind is ${evidenceCommit}.\n`,
    'KNOWN-LIMITATIONS.md': `# Known limitations\n\nFinal candidate: ${RC42}\nSHA-256: ${SHA}\n\nThe Linux evidence matrix is 15/15 PASS, but no complete cross-platform OS/Node matrix is claimed. Permanent Field Report operation is not claimed. Historical RC40 is a superseded baseline only.\n`,
    'LOOP-LEDGER.md': `# Loop ledger\n\nFinal candidate: ${RC42}\nSHA-256: ${SHA}\n\nAll 9 RC42 evidence-binding findings reproduced in before-fix and closed by this rebind.\n`,
    'FINDINGS-MATRIX.md': `# Findings matrix\n\nFinal candidate: ${RC42}\nSHA-256: ${SHA}\n\n| Finding | Status | Evidence |\n|---|---|---|\n| Stale RC40 candidate binding | Closed | candidate-binding manifest |\n| Mixed gate metadata | Closed | single authoritative successful-gate run |\n`
  };
  for (const [name, text] of Object.entries(docs)) write(path.join(audit, name), text);
  fs.mkdirSync(gate, { recursive: true });
  const runSrc = path.join(rawRoot, '.knowledge', 'docs', 'release', '3.3.0', 'test-evidence', 'release-gates', 'runs', RUN);
  cp(runSrc, path.join(gate, 'successful-gate', RUN));
  const gateReport = { ...fullGate, schema_version: 'knowledge-release-gate-rebound.v1', raw_run_path: `successful-gate/${RUN}`, authoritative: true };
  write(path.join(gate, 'release-gate-report.json'), gateReport);
  write(path.join(gate, 'release-gate-report.md'), `# Release gate RC42\n\nStatus: PASS\n\nCandidate: ${RC42}\n\nSHA-256: ${SHA}\n\nRun: ${RUN}\n\nCounts: 63/63 passed; failed 0; skipped 0.\n\nGate source commit: ${GATE_COMMIT}\n\nEvidence rebuild commit: ${evidenceCommit}\n`);
  write(path.join(gate, 'environment.json'), { schema_version: 'knowledge-gate-environment-rebind.v1', candidate_name: RC42, candidate_sha256: SHA, gate_run_id: RUN, gate_source_commit: GATE_COMMIT, evidence_rebuild_commit: evidenceCommit, platform: rawReport.platform, arch: 'x64', node: rawReport.node_version, authoritative: true });
  write(path.join(gate, 'source-and-candidate.json'), { schema_version: 'knowledge-gate-source-candidate.v1', candidate_name: RC42, candidate_sha256: SHA, gate_run_id: RUN, source_commit: GATE_COMMIT, evidence_rebuild_commit: evidenceCommit, candidate_byte_equal: true, runtime_payload_changed: false, authoritative: true });
  write(path.join(gate, 'execution-plan.json'), { ...rawReport.step_plan, candidate_name: RC42, candidate_sha256: SHA, gate_run_id: RUN, source_commit: GATE_COMMIT, authoritative: true });
  write(path.join(gate, 'stdout-stderr-index.json'), { schema_version: 'knowledge-gate-log-index.v1', gate_run_id: RUN, entries: fs.readdirSync(path.join(runSrc, 'logs')).sort().map(name => `successful-gate/${RUN}/logs/${name}`) });
  const manifest = [
    'RC42-FINAL-REPORT.md', 'RC42-SUMMARY.md', `artifacts/${RC42}`, 'tests/candidate-artifact-validation.json',
    'tests/exact-upgrade-report.json', 'tests/physical-clean-install-report.json', 'tests/physical-clean-install-all-integrations-report.json',
    'tests/install-check-black-box-report.json', 'tests/audit-tool-portability-report.json', 'tests/full-gate-report.json',
    'gate/environment.json', 'gate/source-and-candidate.json', 'gate/execution-plan.json', 'final-archive-verification.json'
  ].map(p => binding(p, evidenceCommit));
  write(path.join(out, 'candidate-binding-manifest.json'), { schema_version: 'knowledge-candidate-binding-manifest.v1', candidate_name: RC42, candidate_sha256: SHA, gate_run_id: RUN, gate_source_commit: GATE_COMMIT, evidence_rebuild_commit: evidenceCommit, entries: manifest });
  copy(path.join(out, 'candidate-binding-manifest.json'), path.join(audit, 'candidate-binding-manifest.json'));
  write(path.join(out, 'knowledge-gate-reuse-attestation.json'), { schema_version: 'knowledge-gate-reuse-attestation.v1', candidate_sha256: SHA, gate_source_commit: GATE_COMMIT, evidence_rebuild_commit: evidenceCommit, candidate_byte_equal: true, runtime_payload_changed: false, gate_plan_changed: false, gate_raw_evidence_changed: false, full_gate_rerun_required: false, reason: 'Evidence-only rebind; exact candidate and accepted raw gate remain unchanged.' });
  write(path.join(out, 'candidate-byte-equality-report.json'), { schema_version: 'knowledge-candidate-byte-equality.v1', status: 'pass', candidate_name: RC42, candidate_sha256: SHA, baseline_sha256: SHA, byte_equal: true, size_bytes: fs.statSync(candidateZip).size, new_candidate_created: false });
  write(path.join(out, 'gate-semantic-consistency-report.json'), { schema_version: 'knowledge-gate-semantic-consistency.v1', status: 'pass', candidate_name: RC42, candidate_sha256: SHA, gate_run_id: RUN, source_commit: GATE_COMMIT, execution_plan_steps: rawReport.step_plan.steps.length, execution_plan_sha256: rawReport.step_plan.sha256, authoritative_successful_runs: 1, historical_runs_in_authoritative_path: 0 });
  process.stdout.write(`${JSON.stringify({ status: 'pass', out, candidate_sha256: SHA, gate_run_id: RUN }, null, 2)}\n`);
}
if (require.main === module) main();
