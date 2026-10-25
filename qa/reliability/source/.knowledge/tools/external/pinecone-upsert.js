#!/usr/bin/env node
'use strict';
const fs=require('fs'); const path=require('path'); const pc=require('./pinecone-common');
function parse(argv){return{dryRun:argv.includes('--dry-run')}}
function collect(){const kr=pc.knowledgeRoot(); const vectors=[]; for(const f of pc.sourceFiles()){const text=fs.readFileSync(f,'utf8'); const rel=path.relative(pc.repoRoot(),f).replace(/\\/g,'/'); pc.chunk(text).forEach((chunk,i)=>vectors.push({id:`${pc.sha(rel).slice(0,12)}-${i}`,sparseValues:pc.sparse(chunk),metadata:{source_uri:rel,chunk_index:i,chunk_text:chunk.slice(0,1800),sha256:pc.sha(chunk),trust:'external_unverified',source_of_truth:false}}))} return vectors}
async function main(){const opt=parse(process.argv.slice(2)); const e=pc.env(); const vectors=collect(); const body={namespace:e.namespace,vectors}; const summary={pinecone_mode:e.mode,configured:e.configured,api_key_required:e.apiKeyRequired,dry_run:opt.dryRun||!e.configured,vector_count:vectors.length,namespace:e.namespace,source_of_truth:false,note:'Pinecone Local or Cloud bridge is optional. Retrieved chunks are context, not truth.'}; if(summary.dry_run){console.log(JSON.stringify(summary,null,2));return} console.log(JSON.stringify(await pc.request('/vectors/upsert',body),null,2))}
if(require.main===module)main().catch(e=>{console.error(e.stack||e.message);process.exit(1)});
