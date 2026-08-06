#!/usr/bin/env node
'use strict';

// Standalone semantic verifier for an extracted RC42 audit/gate pair.
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const RC42 = 'knowledge-v3.3.0-step1-rc4-r42.zip';
const SHA = 'ebdeebd5b67ca3ec4f61779e28fd3018e5eee697b00d1705d194b733b41259f0';
const RUN = '2026-08-03T12-11-35-103Z';
const COMMIT = '738d6191ba5f5064bd97d4a9ededd1bb3c535e09';
const PLAN = 'f688c124aea6812d681c546952ab14e0a5bf3ced2431cd417a8a64d70bdb59b6';
function arg(n) { const i = process.argv.indexOf(n); return i >= 0 ? process.argv[i + 1] || null : null; }
function hash(f) { return crypto.createHash('sha256').update(fs.readFileSync(f)).digest('hex'); }
function json(f) { return JSON.parse(fs.readFileSync(f, 'utf8')); }
function walk(root, out = []) { for (const e of fs.readdirSync(root, { withFileTypes: true })) { const p = path.join(root, e.name); if (e.isDirectory()) walk(p, out); else if (e.isFile()) out.push(p); } return out; }
function main() {
  const audit = path.resolve(arg('--audit') || ''); const gate = path.resolve(arg('--gate') || ''); const candidate = path.resolve(arg('--candidate') || ''); const out = path.resolve(arg('--out') || '');
  if (![audit, gate, candidate, out].every(Boolean)) throw new Error('Usage: verify-rc42-evidence-binding.js --audit <extracted> --gate <extracted> --candidate <zip> --out <report.json>');
  const findings = []; const check = (id, pass, code, detail) => findings.push({ id, pass, code: pass ? null : code, detail });
  check('candidate_exact', path.basename(candidate) === RC42 && hash(candidate) === SHA, 'STALE_RC40_BINDING', 'candidate name/SHA must be exact RC42');
  const required = ['tests/candidate-artifact-validation.json','tests/exact-upgrade-report.json','tests/physical-clean-install-report.json','tests/physical-clean-install-all-integrations-report.json','tests/install-check-black-box-report.json','tests/audit-tool-portability-report.json','tests/full-gate-report.json'];
  for (const rel of required) {
    const f = path.join(audit, rel); const exists = fs.existsSync(f); check(`required:${rel}`, exists, 'MISSING_REQUIRED_REPORT', rel);
    if (exists) { const x = json(f); check(`binding:${rel}`, x.candidate_name === RC42 && x.candidate_sha256 === SHA, 'STALE_RC40_BINDING', rel); }
  }
  const docs = ['README.md','RC42-FINAL-REPORT.md','RC42-SUMMARY.md'];
  for (const n of docs) { const f = path.join(audit,n); const t = fs.existsSync(f) ? fs.readFileSync(f,'utf8') : ''; check(`doc:${n}`, t.includes(RC42) && t.includes(SHA) && !/final candidate[^\n]*RC40/i.test(t), 'STALE_RC40_BINDING', n); }
  const embedded = path.join(audit,'artifacts',RC42); check('embedded_candidate', fs.existsSync(embedded) && hash(embedded) === SHA && fs.readFileSync(embedded).equals(fs.readFileSync(candidate)), 'EMBEDDED_CANDIDATE_MISMATCH', embedded);
  const gateReportPath = path.join(gate,'release-gate-report.json'); const gr = fs.existsSync(gateReportPath) ? json(gateReportPath) : {};
  check('gate_report_binding', gr.candidate_name === RC42 && gr.candidate_sha256 === SHA && gr.gate_run_id === RUN && gr.gate_source_commit === COMMIT && gr.steps_total === 63 && gr.passed === 63 && gr.failed === 0 && gr.skipped === 0, 'MIXED_GATE_METADATA', gateReportPath);
  for (const n of ['environment.json','source-and-candidate.json']) { const f=path.join(gate,n); const x=fs.existsSync(f)?json(f):{}; check(`gate:${n}`, x.candidate_name===RC42 && x.candidate_sha256===SHA && x.gate_run_id===RUN && (x.gate_source_commit||x.source_commit)===COMMIT, 'MIXED_GATE_METADATA',n); }
  const planPath=path.join(gate,'execution-plan.json'); const plan=fs.existsSync(planPath)?json(planPath):{}; check('execution_plan', Array.isArray(plan.steps)&&plan.steps.length===63&&plan.sha256===PLAN, 'MIXED_GATE_METADATA',planPath);
  const success=path.join(gate,'successful-gate'); const dirs=fs.existsSync(success)?fs.readdirSync(success,{withFileTypes:true}).filter(x=>x.isDirectory()).map(x=>x.name):[]; check('single_authoritative_run', dirs.length===1&&dirs[0]===RUN, 'MIXED_GATE_METADATA',dirs);
  const manifestPath=path.join(audit,'candidate-binding-manifest.json'); const manifest=fs.existsSync(manifestPath)?json(manifestPath):{}; check('binding_manifest', Array.isArray(manifest.entries)&&manifest.entries.length>=14&&manifest.entries.every(x=>x.authoritative&&x.candidate_name===RC42&&x.candidate_sha256===SHA&&x.gate_run_id===RUN&&x.source_commit===COMMIT), 'STALE_RC40_BINDING',manifestPath);
  // Checksums are intentionally verified after extraction; the packer puts the
  // checksum file itself outside its own manifest.
  for (const root of [audit,gate]) { const m=path.join(root,'CHECKSUMS.sha256'); let ok=fs.existsSync(m); if(ok) for(const line of fs.readFileSync(m,'utf8').trim().split(/\r?\n/)){const q=line.match(/^([a-f0-9]{64})  (.+)$/); if(!q||!fs.existsSync(path.join(root,...q[2].split('/'))) || hash(path.join(root,...q[2].split('/'))) !== q[1]) {ok=false;break;}} check(`checksums:${path.basename(root)}`,ok,'CHECKSUM_MISMATCH',m); }
  const report={schema_version:'knowledge-rc42-binding-verification.v1',status:findings.every(x=>x.pass)?'pass':'fail',candidate_name:RC42,candidate_sha256:SHA,gate_run_id:RUN,gate_source_commit:COMMIT,checks_total:findings.length,passed:findings.filter(x=>x.pass).length,failed:findings.filter(x=>!x.pass).length,findings};
  fs.mkdirSync(path.dirname(out),{recursive:true}); fs.writeFileSync(out,`${JSON.stringify(report,null,2)}\n`,'utf8'); process.stdout.write(`${JSON.stringify(report,null,2)}\n`); if(report.status!=='pass') process.exitCode=2;
}
if(require.main===module)main();
