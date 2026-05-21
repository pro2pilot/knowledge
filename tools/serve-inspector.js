#!/usr/bin/env node
'use strict';
const http=require('http'); const fs=require('fs'); const path=require('path');
const knowledgeRoot=path.resolve(__dirname,'..'); const port=Number(process.env.KNOWLEDGE_INSPECTOR_PORT||8765);
function read(rel){try{return JSON.parse(fs.readFileSync(path.join(knowledgeRoot,rel),'utf8'))}catch{return null}}
function html(){const route=read('maintenance/routing_bundle.json')||{}; const quality=read('maintenance/quality_report.json')||{}; const wiki=read('maps/wiki_graph.json')||{}; return `<!doctype html><meta charset=utf-8><title>.knowledge Inspector</title><style>body{font-family:system-ui;margin:40px;max-width:1100px}pre{background:#111;color:#eee;padding:16px;border-radius:8px;overflow:auto}.card{border:1px solid #ddd;border-radius:8px;padding:16px;margin:12px 0}</style><h1>.knowledge Inspector</h1><div class=card><b>Project:</b> ${route.project?.name||'unknown'}<br><b>Doctor:</b> ${quality.status||'unknown'} ${quality.quality_score??''}<br><b>Wiki graph:</b> ${wiki.node_count||0} nodes / ${wiki.edge_count||0} edges</div><h2>Routing bundle</h2><pre>${escape(JSON.stringify(route,null,2))}</pre>`}
function escape(s){return String(s).replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]))}
http.createServer((req,res)=>{res.writeHead(200,{'Content-Type':'text/html; charset=utf-8'});res.end(html())}).listen(port,()=>console.log(`Inspector: http://localhost:${port}`));
