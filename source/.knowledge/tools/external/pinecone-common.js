'use strict';
const fs=require('fs'); const path=require('path'); const crypto=require('crypto');
const {resolveKnowledgeContext}=require('../lib/path-context');
const {assertSafeContainedPath,assertSafeContainmentRoot}=require('../lib/json-store');
function knowledgeRoot(){return resolveKnowledgeContext().projectKnowledgeRoot}
function repoRoot(){return resolveKnowledgeContext().targetRoot}
function bool(v){return ['1','true','yes','y','on','local'].includes(String(v||'').toLowerCase())}
function modeFromEnv(host,key){const explicit=String(process.env.PINECONE_MODE||'').toLowerCase(); if(['local','cloud','disabled'].includes(explicit)) return explicit; if(bool(process.env.PINECONE_LOCAL)) return 'local'; if(/^https?:\/\/(localhost|127\.0\.0\.1|0\.0\.0\.0)(:|\/|$)/i.test(host||'')) return 'local'; if(host&&key) return 'cloud'; return 'disabled'}
function env(){const host=(process.env.PINECONE_LOCAL_HOST||process.env.PINECONE_HOST||process.env.PINECONE_INDEX_HOST||'').replace(/\/$/,''); const apiKey=process.env.PINECONE_API_KEY||''; const mode=modeFromEnv(host,apiKey); return {mode,enabled:mode!=='disabled',isLocal:mode==='local',isCloud:mode==='cloud',apiKeyRequired:mode==='cloud',host,apiKey,namespace:process.env.PINECONE_NAMESPACE||'default',index:process.env.PINECONE_INDEX||'',configured:mode!=='disabled'&&!!host&&(mode==='local'||!!apiKey)}}
function assertReady(e=env()){if(!e.enabled) throw new Error('Pinecone bridge is disabled. Set PINECONE_MODE=local for Pinecone Local or PINECONE_MODE=cloud for Pinecone Cloud.'); if(!e.host) throw new Error('PINECONE_HOST is required. For Pinecone Local use e.g. http://localhost:5082; for Pinecone Cloud use the unique index host.'); if(e.isCloud&&!e.apiKey) throw new Error('PINECONE_API_KEY is required for Pinecone Cloud. Pinecone Local does not require an API key.')}
function tokenize(text){return String(text||'').toLowerCase().match(/[\p{L}0-9_./:-]{2,}/gu)||[]}
function sparse(text){const counts=new Map(); for(const t of tokenize(text)) counts.set(t,(counts.get(t)||0)+1); const items=[...counts.entries()].sort((a,b)=>b[1]-a[1]).slice(0,256); return {indices:items.map(([t])=>crypto.createHash('sha1').update(t).digest().readUInt32BE(0)&0x7fffffff), values:items.map(([,c])=>Number(Math.log(1+c).toFixed(6)))}}
function sha(text){return crypto.createHash('sha256').update(String(text||'')).digest('hex')}
function chunk(text, max=2200, overlap=240) {
  if (!Number.isSafeInteger(max) || max < 1 || !Number.isSafeInteger(overlap) || overlap < 0 || overlap >= max) {
    const error=new Error('Chunk max must be a positive integer and overlap must be an integer in [0, max).');
    error.code='pinecone_chunk_options_invalid'; throw error;
  }
  text=String(text||'').replace(/^\uFEFF/,'');
  if(text.length<=max) return [text];
  const out=[]; let start=0;
  while(start<text.length) {
    let end=Math.min(text.length,start+max);
    if(end<text.length) {const cut=text.slice(start,end).lastIndexOf('\n\n'); if(cut>max*.55) end=start+cut;}
    const part=text.slice(start,end).trim(); if(part) out.push(part);
    if(end>=text.length) break;
    // Even a paragraph boundary shorter than the overlap must make progress.
    start=Math.max(start+1,end-overlap);
  }
  return out;
}
function readJson(file,fallback={}) {
  try{return JSON.parse(fs.readFileSync(file,'utf8').replace(/^\uFEFF/,''))}
  catch(error){if(error.code==='ENOENT') return fallback; throw error;}
}
function sourceError(message) {const error=new Error(message); error.code='pinecone_source_invalid'; return error;}
function sourceFiles() {
  const context=resolveKnowledgeContext();
  const kr=assertSafeContainmentRoot(context.projectKnowledgeRoot);
  const target=assertSafeContainmentRoot(context.targetRoot);
  const configFile=path.join(kr,'external_memory','pinecone_sources.json');
  assertSafeContainedPath(kr,configFile,{allowMissing:true});
  if(fs.existsSync(configFile) && (!fs.lstatSync(configFile).isFile() || fs.lstatSync(configFile).nlink!==1)) {
    throw sourceError('Pinecone source configuration must be a physical file with one link.');
  }
  const cfg=readJson(configFile,{});
  if(!cfg || typeof cfg!=='object' || Array.isArray(cfg) || (cfg.sources!==undefined && !Array.isArray(cfg.sources))) {
    throw sourceError('Pinecone source configuration must be an object with a sources array.');
  }
  const files=new Set();
  const skipped=new Set(['.git','node_modules','.lock','.runtime','outbox','query_logs']);
  function walk(root,absolute) {
    assertSafeContainedPath(root,absolute,{allowMissing:true});
    if(!fs.existsSync(absolute)) return;
    const stat=fs.lstatSync(absolute);
    if(stat.isDirectory()) {
      for(const name of fs.readdirSync(absolute).sort()) if(!skipped.has(name)) walk(root,path.join(absolute,name));
    } else if(stat.isFile() && /\.(md|txt|json|yaml|yml)$/i.test(absolute)) {
      if(stat.nlink!==1) throw sourceError('Pinecone sources cannot be hardlinked files.');
      files.add(absolute);
    } else if(!stat.isFile()) throw sourceError('Pinecone sources must be physical directories or regular files.');
  }
  for(const source of cfg.sources||[]) {
    if(!source || typeof source!=='object' || Array.isArray(source)) throw sourceError('Each Pinecone source must be an object.');
    if(source.enabled===false) continue;
    const relative=source.path||source.file||source.source_uri;
    if(!relative) continue;
    if(typeof relative!=='string' || path.isAbsolute(relative) || /^[a-z]:/i.test(relative) || relative.replace(/\\/g,'/').split('/').includes('..')) {
      throw sourceError('Pinecone sources must be paths inside the selected project.');
    }
    walk(target,path.resolve(target,relative.replace(/\\/g,'/')));
  }
  if(!files.size) walk(kr,path.join(kr,'external_memory','sources'));
  return [...files].sort();
}
async function request(pathSuffix,body){const e=env(); assertReady(e); const headers={'Content-Type':'application/json'}; if(e.apiKey) headers['Api-Key']=e.apiKey; const res=await fetch(`${e.host}${pathSuffix}`,{method:'POST',headers,body:JSON.stringify(body)}); const text=await res.text(); let json={}; try{json=text?JSON.parse(text):{}}catch{json={raw:text}} if(!res.ok){const err=new Error(`Pinecone request failed: ${res.status} ${res.statusText}`); err.response=json; throw err} return json}
module.exports={knowledgeRoot,repoRoot,env,assertReady,tokenize,sparse,sha,chunk,sourceFiles,request,readJson};
