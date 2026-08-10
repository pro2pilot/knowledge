#!/usr/bin/env node
'use strict';
import fs from 'node:fs';
import path from 'node:path';

const ROOT = path.resolve(path.dirname(new URL(import.meta.url).pathname), '..');
const args = Object.fromEntries(process.argv.slice(2).map((x) => {
  const m=x.match(/^--([^=]+)=(.*)$/); return m ? [m[1],m[2]] : [x.replace(/^--/,''),true];
}));
const resultsRoot = path.resolve(args.results || path.join(ROOT, 'results'));
const outRoot = path.resolve(args.out || resultsRoot);
fs.mkdirSync(outRoot,{recursive:true});
const tasks = JSON.parse(fs.readFileSync(path.join(ROOT,'TASKS.json'),'utf8'));
const gold = JSON.parse(fs.readFileSync(path.join(ROOT,'GOLD-ANSWERS.json'),'utf8'));

function choose(n,k){ if(k<0||k>n)return 0; k=Math.min(k,n-k); let r=1; for(let i=1;i<=k;i++)r=r*(n-k+i)/i; return r; }
function exactTwoSidedMcNemar(b,c){ const n=b+c; if(!n)return 1; const p=x=>choose(n,x)*0.5**n; const obs=p(Math.min(b,c)); let total=0; for(let x=0;x<=n;x++)if(p(x)<=obs+1e-15)total+=p(x); return Math.min(1,total); }
function wilson(k,n,z=1.959963984540054){ if(!n)return [null,null]; const ph=k/n, d=1+z*z/n; const center=(ph+z*z/(2*n))/d; const half=z*Math.sqrt(ph*(1-ph)/n+z*z/(4*n*n))/d; return [Math.max(0,center-half),Math.min(1,center+half)]; }
function exact(actual,expected){ return actual && actual.target_module===expected.target_module && actual.required_dependency===expected.required_dependency && actual.first_source_file===expected.first_source_file; }

const pairs=[]; const missing=[]; const invalid=[];
for(const task of tasks){
  const row={task_id:task.task_id,family:task.family,order:task.order};
  for(const cond of ['W','K']){
    const p=path.join(resultsRoot,`${task.task_id}-${cond}`,'RESULT.json');
    if(!fs.existsSync(p)){ missing.push(`${task.task_id}-${cond}`); continue; }
    const r=JSON.parse(fs.readFileSync(p,'utf8'));
    if(r.infrastructure_failure){ invalid.push({input_id:r.input_id,reason:r.error||'infrastructure_failure'}); }
    row[cond]={...r,pass:!r.infrastructure_failure && exact(r.output,gold[task.task_id])};
  }
  pairs.push(row);
}
const complete=pairs.filter(p=>p.W&&p.K&&!p.W.infrastructure_failure&&!p.K.infrastructure_failure);
const w=complete.filter(p=>p.W.pass).length, k=complete.filter(p=>p.K.pass).length;
const kOnly=complete.filter(p=>!p.W.pass&&p.K.pass).length;
const wOnly=complete.filter(p=>p.W.pass&&!p.K.pass).length;
const both=complete.filter(p=>p.W.pass&&p.K.pass).length;
const neither=complete.filter(p=>!p.W.pass&&!p.K.pass).length;
const p=exactTwoSidedMcNemar(wOnly,kOnly);
const wRate=complete.length?w/complete.length:null, kRate=complete.length?k/complete.length:null;
const delta=complete.length?(kRate-wRate)*100:null;
let tier='unsupported';
if(complete.length===32 && invalid.length===0 && k>w && p<0.05 && delta>=20) tier='tier_a';
else if(complete.length===32 && invalid.length===0 && k>w && p<0.05) tier='tier_b';
else if(k>w) tier='tier_c';
const wording = tier==='tier_a'
 ? `In a preregistered 32-pair synthetic repository-navigation study under the same maximum first-read budget, .knowledge task-scoped context improved the same model's exact first-pass repository-decision accuracy from ${(wRate*100).toFixed(1)}% (${w}/32) to ${(kRate*100).toFixed(1)}% (${k}/32), a ${delta.toFixed(1)} percentage-point increase (exact McNemar p=${p.toFixed(6)}).`
 : tier==='tier_b'
 ? `In a preregistered 32-pair synthetic repository-navigation study, exact first-pass repository-decision accuracy increased from ${(wRate*100).toFixed(1)}% to ${(kRate*100).toFixed(1)}% with task-scoped context (exact McNemar p=${p.toFixed(6)}).`
 : tier==='tier_c'
 ? `The task-scoped condition was exact on ${k}/32 decisions versus ${w}/32 for workspace-wide context; the result is descriptive and not statistically conclusive (p=${p.toFixed(6)}).`
 : 'The study did not support an accuracy-improvement claim.';
const report={
 schema_version:'knowledge-hard-accuracy-study.v1',status:missing.length||invalid.length?'incomplete':'complete',tier,
 candidate_sha256:'44085f441946ca08905bacdd329ff5c7a68aeefeb25b04389bf3c2cdb4de961a',
 metrics:{pairs_complete:complete.length,workspace_correct:w,task_scoped_correct:k,workspace_accuracy:wRate,task_scoped_accuracy:kRate,absolute_delta_percentage_points:delta,both_correct:both,workspace_only_wins:wOnly,task_scoped_only_wins:kOnly,neither_correct:neither,mcnemar_exact_two_sided_p:p,workspace_wilson_95: wilson(w,complete.length),task_scoped_wilson_95:wilson(k,complete.length),missing:missing.length,infrastructure_failures:invalid.length},
 claim:{status:tier,wording,required_limitation:'This measures first-pass repository-decision accuracy on synthetic current-vs-legacy navigation tasks under a fixed first-read budget. It does not mean the underlying model became intrinsically more intelligent, and it does not measure complete coding-task accuracy.'},
 missing,invalid,pairs
};
fs.writeFileSync(path.join(outRoot,'HARD-ACCURACY-STUDY.json'),JSON.stringify(report,null,2)+'\n');
fs.writeFileSync(path.join(outRoot,'HARD-ACCURACY-STUDY.md'),[
 '# Hard accuracy study','',`Status: **${report.status.toUpperCase()}**`,`Claim tier: **${tier.toUpperCase()}**`,'',
 `- Workspace-wide: ${w}/${complete.length}`,
 `- Task-scoped: ${k}/${complete.length}`,
 `- Absolute delta: ${delta===null?'n/a':delta.toFixed(1)+' percentage points'}`,
 `- Task-scoped-only wins: ${kOnly}`,
 `- Workspace-only wins: ${wOnly}`,
 `- Exact McNemar p: ${p.toFixed(6)}`,'','## Permitted wording','',wording,'','## Required limitation','',report.claim.required_limitation,''
].join('\n'));
console.log(JSON.stringify({status:report.status,tier,metrics:report.metrics},null,2));
if(report.status!=='complete') process.exitCode=2;
