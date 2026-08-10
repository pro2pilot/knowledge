#!/usr/bin/env node
'use strict';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { spawnSync } from 'node:child_process';

const ROOT=path.resolve(path.dirname(new URL(import.meta.url).pathname),'..');
const TOKEN=process.env.GITHUB_TOKEN;
const MODEL=process.env.HARD_ACCURACY_MODEL||'openai/gpt-4.1-mini';
const API='https://models.github.ai/inference/chat/completions';
const OUT=path.resolve(process.env.HARD_ACCURACY_OUT||path.join(ROOT,'results'));
const DELAY_MS=Number(process.env.HARD_ACCURACY_DELAY_MS||8500);
if(!TOKEN) throw new Error('GITHUB_TOKEN is required and must have models: read');
fs.mkdirSync(OUT,{recursive:true});
const manifest=JSON.parse(fs.readFileSync(path.join(ROOT,'INPUT-MANIFEST.json'),'utf8'));
const tasks=JSON.parse(fs.readFileSync(path.join(ROOT,'TASKS.json'),'utf8'));
const order=[];
const taskById=new Map(tasks.map(t=>[t.task_id,t]));
for(const t of tasks){ for(const c of t.order==='W_FIRST'?['W','K']:['K','W']) order.push(`${t.task_id}-${c}`); }
// Deterministic interleaving by task hash, preserving each pair's declared within-pair order.
order.sort((a,b)=>crypto.createHash('sha256').update(`34001:${a.split('-').slice(0,2).join('-')}`).digest('hex').localeCompare(crypto.createHash('sha256').update(`34001:${b.split('-').slice(0,2).join('-')}`).digest('hex')) || a.localeCompare(b));
const assignments=new Map(manifest.inputs.map(x=>[x.input_id,x]));
const sleep=ms=>new Promise(r=>setTimeout(r,ms));
const sha=b=>crypto.createHash('sha256').update(b).digest('hex');
function writeJson(p,v){fs.mkdirSync(path.dirname(p),{recursive:true});fs.writeFileSync(p,JSON.stringify(v,null,2)+'\n');}
async function requestWithRetry(body){
 const attempts=[];
 for(let attempt=1;attempt<=5;attempt++){
  const started=new Date().toISOString();
  let response,text;
  try{
   response=await fetch(API,{method:'POST',headers:{Authorization:`Bearer ${TOKEN}`,'Content-Type':'application/json',Accept:'application/vnd.github+json','X-GitHub-Api-Version':'2026-03-10'},body:JSON.stringify(body)});
   text=await response.text();
  }catch(error){
   attempts.push({attempt,started,status:null,error:String(error)});
   if(attempt===5)throw Object.assign(new Error(String(error)),{attempts});
   await sleep(8000*attempt); continue;
  }
  attempts.push({attempt,started,status:response.status,response_sha256:sha(text)});
  if(response.ok) return {payload:JSON.parse(text),attempts};
  const retryable=[408,409,425,429,500,502,503,504].includes(response.status);
  if(!retryable||attempt===5){ const e=new Error(`GitHub Models ${response.status}: ${text.slice(0,1000)}`); e.attempts=attempts; throw e; }
  const retryAfter=Number(response.headers.get('retry-after'));
  await sleep(Number.isFinite(retryAfter)&&retryAfter>0?retryAfter*1000:8000*attempt);
 }
}
for(let i=0;i<order.length;i++){
 const inputId=order[i], assignment=assignments.get(inputId), dir=path.join(OUT,inputId), resultPath=path.join(dir,'RESULT.json');
 fs.mkdirSync(dir,{recursive:true});
 if(fs.existsSync(resultPath)){
  const prior=JSON.parse(fs.readFileSync(resultPath,'utf8'));
  if(!prior.infrastructure_failure) continue;
 }
 const inputPath=path.join(ROOT,'inputs',inputId,'INPUT.md');
 const input=fs.readFileSync(inputPath);
 if(sha(input)!==assignment.input_sha256) throw new Error(`Input SHA mismatch ${inputId}`);
 const body={model:MODEL,temperature:0,seed:34001+i,max_tokens:180,response_format:{type:'json_object'},messages:[
  {role:'system',content:'Use only the supplied first-read context. Return exactly one JSON object with target_module, required_dependency, first_source_file. No markdown or explanation.'},
  {role:'user',content:input.toString('utf8')}
 ]};
 const startedAt=new Date().toISOString(); const started=Date.now();
 try{
  const {payload,attempts}=await requestWithRetry(body);
  const raw=payload.choices?.[0]?.message?.content||'';
  let output=null,parseError=null; try{output=JSON.parse(raw);}catch(e){parseError=String(e);}
  const result={schema_version:'hard-accuracy-result.v1',input_id:inputId,task_id:assignment.task_id,condition:assignment.condition,input_sha256:assignment.input_sha256,model_requested:MODEL,model_reported:payload.model||null,started_at:startedAt,completed_at:new Date().toISOString(),duration_ms:Date.now()-started,output,raw_output_sha256:sha(raw),parse_error:parseError,finish_reason:payload.choices?.[0]?.finish_reason||null,usage:payload.usage||null,infrastructure_failure:false,attempts};
  fs.writeFileSync(path.join(dir,'RAW-OUTPUT.txt'),raw,'utf8'); writeJson(resultPath,result);
  console.log(JSON.stringify({index:i+1,total:order.length,input_id:inputId,status:'complete',usage:payload.usage||null}));
 }catch(error){
  writeJson(resultPath,{schema_version:'hard-accuracy-result.v1',input_id:inputId,task_id:assignment.task_id,condition:assignment.condition,input_sha256:assignment.input_sha256,model_requested:MODEL,started_at:startedAt,completed_at:new Date().toISOString(),duration_ms:Date.now()-started,infrastructure_failure:true,error:String(error.message||error),attempts:error.attempts||[]});
  console.error(JSON.stringify({index:i+1,total:order.length,input_id:inputId,status:'infrastructure_failure',error:String(error.message||error)}));
 }
 if(i<order.length-1) await sleep(DELAY_MS);
}
const score=spawnSync(process.execPath,[path.join(ROOT,'tools','score-hard-accuracy.mjs'),`--results=${OUT}`,`--out=${OUT}`],{stdio:'inherit'});
process.exitCode=score.status||0;
