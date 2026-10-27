'use strict';
// A real 125-second silent project step crosses the historical 120-second
// child timeout. Product setup/work/progress/cleanup defaults are unchanged.
const test = require('node:test'), assert = require('node:assert/strict');
const fs = require('node:fs'), path = require('node:path'), os = require('node:os');
const flow = require('../tools/flow');
const { resolveKnowledgeContext } = require('../tools/lib/path-context');
const names = ['sync-tracked.js','build-wiki-graph.js','lint-wiki.js','external-memory-status.js',
  'build-routing-bundle.js','build-search-index.js','scan-secrets.js','doctor.js',
  'build-visual-inspector.js','collect-metrics.js','generate-pr-summary.js','render-graph-execution.js','apply-template.js'];
test('ordinary Flow permits a real silent 125-second step with default work and progress budgets',
  { skip: !['linux','win32'].includes(process.platform), timeout: 300000 }, async t => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(),'flow-long-work-')), system = path.join(root,'.knowledge');
    const proof = path.join(root,'actual-work.json');
    fs.mkdirSync(path.join(system,'tools'),{recursive:true});
    fs.writeFileSync(path.join(system,'config.yaml'),'updates:\n  enabled: false\n');
    fs.writeFileSync(path.join(system,'package.json'),'{"version":"3.4.4"}');
    for (const name of names) fs.writeFileSync(path.join(system,'tools',name),'console.log(JSON.stringify({status:"ok"}));\n');
    fs.writeFileSync(path.join(system,'tools/sync-tracked.js'),
      `const start=process.hrtime.bigint();setTimeout(()=>{const elapsed_ms=Number(process.hrtime.bigint()-start)/1e6;` +
      `require('fs').writeFileSync(${JSON.stringify(proof)},JSON.stringify({elapsed_ms,silent:true}));console.log('{"status":"ok"}');},125000);`);
    const context = resolveKnowledgeContext({__skipCli:true,mode:'repo',systemRoot:system,targetRoot:root,projectKnowledgeRoot:system});
    const controller = new AbortController(); let drained = false;
    const abort = () => controller.abort(); t.signal.addEventListener('abort',abort,{once:true});
    try {
      const out = await flow.runFlowAsync({name:'doctor',context,json:true,quiet:true},{signal:controller.signal});
      drained = out.ownership?.cleanup?.status === 'completed';
      assert.equal(out.status,'ok',JSON.stringify(out));assert.equal(out.steps_total,8);assert.equal(out.steps_ok,8);
      assert.equal(out.command_cleanup?.status,'completed');assert.equal(drained,true);
      const actual = JSON.parse(fs.readFileSync(proof,'utf8'));
      assert.equal(actual.silent,true);assert.ok(actual.elapsed_ms >= 125000,JSON.stringify(actual));
      t.diagnostic(JSON.stringify({actual_silent_work_ms:actual.elapsed_ms,outer_cleanup:'completed',inner_cleanup:'completed',product_budgets:'default'}));
    } catch (error) {
      drained ||= error.cleanup?.status === 'completed';throw error;
    } finally {
      t.signal.removeEventListener('abort',abort);controller.abort();
      if (drained) fs.rmSync(root,{recursive:true,force:true});
      else t.diagnostic('Fixture retained without complete native drain proof');
    }
  });
