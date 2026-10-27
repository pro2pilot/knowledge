"""Run real generated child code under a deterministic nonprivileged VM fixture."""
import importlib.util
import json
from pathlib import Path
import subprocess
import unittest

source=Path(__file__).resolve().parent/'controller.py'
spec=importlib.util.spec_from_file_location('child_fixture_review',source)
c=importlib.util.module_from_spec(spec);spec.loader.exec_module(c)

HARNESS=r'''
const vm=require('node:vm'),path=require('node:path').posix,assert=require('node:assert/strict');
const {EventEmitter}=require('node:events');const mode=process.argv[1];let text='';
process.stdin.setEncoding('utf8');process.stdin.on('data',x=>text+=x);
process.stdin.on('end',async()=>{
  const files=new Map(), tests=[];let clock=0,compiled=false,interval;
  const ready='/scratch/descendant-ready.json',marker='/scratch/descendant.txt';
  const fakeFs={
    readFileSync(name){if(name==='/source/input.txt')return 'component-slice-input-v1'+String.fromCharCode(10);
      if(!files.has(name)){const e=new Error('missing');e.code='ENOENT';throw e;}return files.get(name);},
    writeFileSync(name,data){if(name==='/source/input.txt'){const e=new Error('readonly');e.code='EROFS';throw e;}files.set(name,data);},
    appendFileSync(name,data){files.set(name,(files.get(name)||'')+data);}
  };
  const spawn=(_exe,args)=>{
    let childCode=args[1];
    if(mode==='wrong-newline'){
      const wrong=childCode.replace("String(++tick)+'\\n'","String(++tick)+'\\\\n'");
      assert.notEqual(wrong,childCode);childCode=wrong;
    }
    const script=new vm.Script(childCode);compiled=true;
    script.runInNewContext({require:name=>{assert.equal(name,'node:fs');return fakeFs;},
      process:{pid:777,getuid:()=>1000010301,version:'v22.17.1'},setInterval:fn=>{interval=fn;return 1;}});
    interval();if(mode!=='exit-between-ticks')interval();
    const child=new EventEmitter();child.pid=777;child.unref=()=>{};
    queueMicrotask(()=>{child.emit('spawn');
      if(mode==='exit-between-ticks'){child.emit('exit',1,null);interval();}
      else if(mode==='ready-then-exit')child.emit('exit',0,null);
    });return child;
  };
  const outer={env:{KNOWLEDGE_SLICE_SCRATCH:'/scratch'},version:'v22.17.1',pid:99,
    getuid:()=>1000010301,geteuid:()=>1000010301,getgid:()=>1000010301,cwd:()=>'/source',execPath:'/runtime/node'};
  const sandbox={require:name=>({'node:test':(_name,fn)=>tests.push(fn),'node:assert/strict':assert,
    'node:fs':fakeFs,'node:path':path,'node:child_process':{spawn}}[name]),process:outer,
    Date:{now:()=>clock},JSON,Promise,Buffer,
    setTimeout:(fn,ms)=>setImmediate(()=>{clock+=ms||0;fn();})};
  try{vm.runInNewContext(text,sandbox);assert.equal(tests.length,1);await tests[0]();
    console.log(JSON.stringify({ok:true,compiled,markerHex:Buffer.from(files.get(marker)||'').toString('hex')}));
  }catch(error){console.log(JSON.stringify({ok:false,compiled,error:error.message,markerHex:Buffer.from(files.get(marker)||'').toString('hex')}));}
});
'''

class Semantics(unittest.TestCase):
    def run_mode(self,mode):
        result=subprocess.run(['node','-e',HARNESS,mode],input=c.test_script_bytes(),capture_output=True,timeout=10,check=True)
        return json.loads(result.stdout)
    def test_actual_generated_child_writes_two_lf_ticks(self):
        got=self.run_mode('normal');self.assertEqual(got,{'ok':True,'compiled':True,'markerHex':'310a320a'})
    def test_valid_but_wrong_newline_child_is_rejected(self):
        got=self.run_mode('wrong-newline');self.assertTrue(got['compiled']);self.assertFalse(got['ok'])
        self.assertIn('readiness/tick proof timed out',got['error']);self.assertEqual(got['markerHex'],'315c6e325c6e')
    def test_exit_between_ticks_cannot_be_overridden_by_late_readiness(self):
        got=self.run_mode('exit-between-ticks');self.assertTrue(got['compiled']);self.assertFalse(got['ok'])
        self.assertIn('exited before readiness',got['error']);self.assertEqual(got['markerHex'],'310a320a')
    def test_exit_after_readiness_does_not_reject_completed_proof(self):
        got=self.run_mode('ready-then-exit');self.assertTrue(got['ok'])

if __name__=='__main__':unittest.main()
