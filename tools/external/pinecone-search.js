#!/usr/bin/env node
'use strict';
const pc=require('./pinecone-common');
function parse(argv){const q=[];const o={dry:false,topK:5};for(const a of argv){if(a==='--dry-run')o.dry=true;else if(a.startsWith('--top-k='))o.topK=Number(a.slice(8))||5;else q.push(a)}return{query:q.join(' ').trim(),...o}}
async function main(){const a=parse(process.argv.slice(2)); if(!a.query){console.log('Usage: node .knowledge/tools/external/pinecone-search.js "query" [--dry-run] [--top-k=5]');return} const e=pc.env(); const body={namespace:e.namespace,topK:a.topK,sparseVector:pc.sparse(a.query),includeMetadata:true,source_of_truth:false}; if(a.dry||!e.configured){console.log(JSON.stringify({pinecone_mode:e.mode,configured:e.configured,dry_run:true,api_key_required:e.apiKeyRequired,request:body,note:'Pinecone Local or Cloud bridge; retrieved chunks are context, not truth.'},null,2));return} console.log(JSON.stringify(await pc.request('/query',body),null,2))}
if(require.main===module)main().catch(e=>{console.error(e.stack||e.message);process.exit(1)});
