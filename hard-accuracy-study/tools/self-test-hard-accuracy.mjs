#!/usr/bin/env node
'use strict';
import fs from 'node:fs'; import path from 'node:path'; import os from 'node:os'; import {spawnSync} from 'node:child_process';
const ROOT=path.resolve(path.dirname(new URL(import.meta.url).pathname),'..');
const tasks=JSON.parse(fs.readFileSync(path.join(ROOT,'TASKS.json'),'utf8')); const gold=JSON.parse(fs.readFileSync(path.join(ROOT,'GOLD-ANSWERS.json'),'utf8'));
const tmp=fs.mkdtempSync(path.join(os.tmpdir(),'hard-accuracy-selftest-'));
function writeResult(task,cond,correct){const d=path.join(tmp,`${task.task_id}-${cond}`);fs.mkdirSync(d,{recursive:true});const g=gold[task.task_id];const output=correct?g:{target_module:'wrong',required_dependency:'wrong',first_source_file:'wrong'};fs.writeFileSync(path.join(d,'RESULT.json'),JSON.stringify({input_id:`${task.task_id}-${cond}`,task_id:task.task_id,condition:cond,output,infrastructure_failure:false},null,2));}
try{
 // Create a known Tier A fixture: W=16/32, K=30/32, K-only=14, W-only=0.
 tasks.forEach((t,i)=>{writeResult(t,'W',i<16);writeResult(t,'K',i<30);});
 const run=spawnSync(process.execPath,[path.join(ROOT,'tools','score-hard-accuracy.mjs'),`--results=${tmp}`,`--out=${tmp}`],{encoding:'utf8'});
 if(run.status!==0)throw new Error(run.stderr||run.stdout);
 const report=JSON.parse(fs.readFileSync(path.join(tmp,'HARD-ACCURACY-STUDY.json'),'utf8'));
 const checks=[report.tier==='tier_a',report.metrics.workspace_correct===16,report.metrics.task_scoped_correct===30,report.metrics.task_scoped_only_wins===14,report.metrics.workspace_only_wins===0,report.metrics.mcnemar_exact_two_sided_p<0.05];
 const out={schema_version:'hard-accuracy-self-test.v1',status:checks.every(Boolean)?'pass':'fail',checks_total:checks.length,passed:checks.filter(Boolean).length,failed:checks.filter(x=>!x).length,report:{tier:report.tier,metrics:report.metrics}};
 console.log(JSON.stringify(out,null,2)); if(out.status!=='pass')process.exitCode=2;
}finally{fs.rmSync(tmp,{recursive:true,force:true});}
