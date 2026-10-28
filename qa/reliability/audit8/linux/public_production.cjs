'use strict';

// Real ordinary-user public API qualification. No product module, native
// observation, execution record, or final acceptance is mocked or patched.
const fs = require('node:fs'), os = require('node:os'), path = require('node:path');
const crypto = require('node:crypto'), assert = require('node:assert/strict');
const { spawn } = require('node:child_process');
const SCHEMA = 'knowledge-audit8-linux-public-production.v1';
const mono = () => process.hrtime.bigint();
const ms = start => Number(mono() - start) / 1e6;
const delay = value => new Promise(resolve => setTimeout(resolve, value));
const sha = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
const fail = (code, details) => Object.assign(new Error(code), { code, ...details });
const boundedError = error => Object.fromEntries(['code','message','stage','timed_out','attempt_id','recovery_required',
  'result_visibility','terminal_commit','teardown','verification_budget','execution'].filter(key => error[key] !== undefined).map(key => [key,error[key]]));

if (process.argv[2] === '--invoke') {
  const runtime = path.resolve(process.argv[3]); let input = '', count = 0;
  process.stdin.setEncoding('utf8');
  process.stdin.on('data', part => { count += Buffer.byteLength(part); if (count > 2 * 1024 * 1024) process.exit(2); input += part; });
  process.stdin.on('end', () => {
    let answer;
    try {
      const request = JSON.parse(input);
      const result = require(path.join(runtime,'tools/lib/repair-on-touch.js')).runVerificationTests(request);
      answer = { schema_version:SCHEMA, status:'returned', uid:process.getuid(),
        records:result.map(item => ({ record:item.record, relative_path:item.relative_path, idempotent:item.idempotent })),
        acceptances:result.verification_acceptances, budget:result.verification_budget };
    } catch (error) { answer = { schema_version:SCHEMA, status:'threw', uid:process.getuid(), error:boundedError(error) }; }
    process.stdout.write(JSON.stringify(answer)+'\n', () => process.exit(0));
  });
} else main().catch(error => { process.stderr.write((error.stack || String(error))+'\n'); process.exitCode = 1; });

async function main() {
  assert.equal(process.platform,'linux'); assert.notEqual(process.getuid(),0,'Public caller must be an ordinary UID');
  const args = {};
  for (let i=2;i<process.argv.length;i++) {
    if(process.argv[i]==='--include-controller-crash'){args['include-controller-crash']=true;continue;}
    assert.ok(['--source','--output','--work-root','--cohort-seconds'].includes(process.argv[i]) && process.argv[i+1], 'Unknown or incomplete argument');
    args[process.argv[i].slice(2)] = process.argv[++i];
  }
  const runtime = path.resolve(args.source || path.resolve(__dirname,'../../../../source/.knowledge'));
  const output = path.resolve(args.output || 'evidence/public-production.json');
  fs.mkdirSync(path.dirname(output),{ recursive:true });
  const root = args['work-root'] ? path.resolve(args['work-root']) : fs.mkdtempSync(path.join(os.tmpdir(),'knowledge-audit8-public-'));
  fs.mkdirSync(root,{ recursive:true });
  const evidence = path.join(path.dirname(output),'public-production-raw'); fs.mkdirSync(evidence,{ recursive:true });
  const repo = path.join(root,'repo'), state = path.join(repo,'.knowledge'); fs.mkdirSync(state,{ recursive:true });
  const core = require(path.join(runtime,'tools/lib/repair-on-touch.js'));
  assert.equal(typeof core.runVerificationTests,'function');
  const control = require(path.join(runtime,'tools/lib/verification-control.js'));
  const finalization = require(path.join(runtime,'tools/lib/verification-finalization.js'));
  const execution = require(path.join(runtime,'tools/lib/verification-execution.js'));
  const { readStableFile } = require(path.join(runtime,'tools/lib/stable-file.js'));
  const service = require(path.join(runtime,'tools/lib/verification-linux-service-finalization.js'));
  const env = require(path.join(runtime,'tools/lib/command-runner.js')).safeEnvironment(process.env);
  const context = { stateRoot:state, projectKnowledgeRoot:state, targetRoot:repo, systemRoot:runtime };
  function sourceInventory() {
    const files={};
    function visit(directory,relative='') {
      for(const entry of fs.readdirSync(directory,{withFileTypes:true})) {
        const name=relative?relative+'/'+entry.name:entry.name,filename=path.join(directory,entry.name);
        if(entry.isDirectory())visit(filename,name);
        else {assert.ok(entry.isFile(),'Qualification source cannot contain symlinks');files[name]=sha(fs.readFileSync(filename));}
      }
    }
    visit(runtime);return Object.fromEntries(Object.entries(files).sort(([a],[b])=>a.localeCompare(b)));
  }
  const initialSource=sourceInventory();
  fs.writeFileSync(path.join(evidence,'SOURCE_BEFORE.json'),JSON.stringify(initialSource,null,2)+'\n');
  const started = mono(), seconds = Number(args['cohort-seconds'] || 600);
  assert.ok(Number.isSafeInteger(seconds) && seconds >= 120 && seconds <= 1200);
  const cohortEnd = started + BigInt(seconds)*1000000000n;
  const report = { schema_version:SCHEMA, status:'FAIL', physical:true, platform:process.platform, arch:process.arch,
    caller_uid:process.getuid(), node:process.version, runtime, fixture_root:root, release_qualified:false,
    source_changes:null, source_before_sha256:sha(Buffer.from(JSON.stringify(initialSource))), fixtures_retained:true,
    cases:[], native_terminal_proofs:[] };
  const save = () => { report.elapsed_ms=ms(started); fs.writeFileSync(output,JSON.stringify(report,null,2)+'\n'); };
  let priorGeneration = null, priorAcceptance = null;
  const unit = "const test=require('node:test'),assert=require('node:assert/strict');test('physical public node test',()=>assert.equal(6*7,42));\n";
  fs.writeFileSync(path.join(repo,'probe.test.js'),unit);
  function request(name, workMs, paired) {
    return { stateRoot:state, repoRoot:repo, taskId:'audit8-'+name, sessionId:'physical-public-linux', checkedBy:'audit8-physical-qa',
      sourceFiles:paired?['probe.js','probe.test.js']:['probe.js'],
      tests:[{ argv:['node','probe.js'],cwd:'.',timeout_ms:workMs },...(paired?[{ argv:['node','--test','probe.test.js'],cwd:'.',timeout_ms:workMs }]:[])],
      timeoutMs:workMs, verificationPolicy:{ work_budget_ms:workMs,no_progress_ms:0,cleanup_budget_ms:15000 },
      nativeExecution:{ linux:{ enabled:true,mode:'isolated_copy',broker_path:'/var/lib/knowledge-linux-native-v1/broker',copy:{} } } };
  }
  function ownClosed(row) {
    assert.equal(row?.exit_observed,true); assert.equal(row?.ipc_closed,true);
    assert.equal(row.native_closure?.pidfd_exit_observed,true);
    assert.equal(row.native_closure?.writer_cgroup_empty,true);
    assert.equal(row.native_closure?.guardian_reaped,true);
    assert.equal(row.native_closure?.registration_removed,true);
  }
  function terminalFrom(attempt) {
    const proof = attempt?.cleanup?.native_transcript?.payload?.native_return;
    assert.equal(proof?.method,'linux_native_service');
    const result = service.validateTerminal({ capability:proof.capability, terminalReply:proof.terminal_reply,
      terminalRaw:proof.terminal_raw, opened:attempt.containment.descriptor.opened,
      successful:proof.terminal_reply.status === 'completed' });
    assert.equal(result.cleanup_confirmed,true); assert.equal(result.cgroup_empty,true);
    if(result.status==='completed')assert.equal(result.commands_drained,result.commands);
    else assert.ok(result.commands_drained>=0 && result.commands_drained<=result.commands,
      'Cancelled command-level replies may be incomplete while the outer native namespace is conclusively drained');
    report.native_terminal_proofs.push({ attempt_id:attempt.attempt_id, generation:attempt.generation,
      terminal_sha256:result.proof_sha256, status:result.status, authority_uid:result.authority_uid,worker_uid:result.worker_uid,
      commands:result.commands,commands_drained:result.commands_drained,output_eof:result.output_eof,
      cleanup_started_ns:result.cleanup_started_ns,cleanup_deadline_ns:result.cleanup_deadline_ns,observed_ns:result.observed_ns });
    return result;
  }
  function persistControl(name,row,attempt) {
    const bytes=readStableFile(state,path.join(state,'maintenance/verification-control/active.json'),{maxBytes:2*1024*1024});
    const physical=JSON.parse(bytes),{owner_token_sha256,root_identity,...view}=physical;
    assert.match(owner_token_sha256,/^[a-f0-9]{64}$/);assert.ok(root_identity);
    assert.equal(finalization.digest(view),finalization.digest(attempt));
    const inspect=value=>{
      if(!value||typeof value!=='object')return;
      for(const [key,child] of Object.entries(value)){
        assert.ok(!/^(?:token|owner_token|private_key|signing_key)$/i.test(key),'Never export private capabilities');inspect(child);
      }
    };inspect(physical);
    const filename=name+'.control.json';fs.writeFileSync(path.join(evidence,filename),bytes);
    row.raw_control=filename;row.control_physical_sha256=sha(bytes);
    fs.writeFileSync(path.join(evidence,name+'.attempt.json'),JSON.stringify(attempt,null,2)+'\n');
  }
  async function observeControllerCrash(name,attempt,callerPid) {
    const descriptor=attempt.containment.descriptor,capability=descriptor.capability,opened=descriptor.opened;
    const observerFile=path.join(__dirname,'observe_parent_crash.py'),observerOutput=path.join(evidence,name+'.observer.json');
    const maximum=BigInt(opened.work_deadline_ns)+BigInt(opened.cleanup_budget_ms)*1000000n;
    const originalEnd=maximum<cohortEnd?maximum:cohortEnd;
    assert.ok(originalEnd>mono(),'No crash observer admission after original endpoint');
    const helper=spawn('python3',[observerFile,'--output',observerOutput],{env,stdio:['pipe','pipe','pipe']});
    let stdout='',stderr='',buffer='',closed=false,exitCode,exitSignal,helperError,readyResolve,readyReject;
    const ready=new Promise((resolve,reject)=>{readyResolve=resolve;readyReject=reject;});
    const done=new Promise(resolve=>helper.once('close',(code,signal)=>{closed=true;exitCode=code;exitSignal=signal;
      readyReject(fail('qa_crash_observer_early_exit',{message:stderr.slice(-4096)}));resolve();}));
    helper.on('error',error=>{helperError=error;readyReject(error);});
    helper.stdin.on('error',error=>{helperError=error;readyReject(error);});
    helper.stderr.on('data',part=>{stderr+=part.toString();if(stderr.length>1024*1024){helperError=fail('qa_crash_observer_output_limit');helper.kill('SIGKILL');}});
    helper.stdout.on('data',part=>{
      stdout+=part.toString();buffer+=part.toString();
      if(stdout.length>1024*1024){helperError=fail('qa_crash_observer_output_limit');helper.kill('SIGKILL');return;}
      for(;;){const newline=buffer.indexOf('\n');if(newline<0)break;const line=buffer.slice(0,newline);buffer=buffer.slice(newline+1);
        try{const value=JSON.parse(line);if(value.status==='READY_WITH_RETAINED_PIDFDS')readyResolve(value);}catch{}}
    });
    const limit=Math.max(1,Math.min(25000,Number(originalEnd-mono())/1e6));
    let deadlineReject;const timedOut=new Promise((_,reject)=>{deadlineReject=reject;});timedOut.catch(()=>{});
    const watchdog=setTimeout(()=>{helperError=fail('qa_crash_observer_timeout');readyReject(helperError);
      deadlineReject(helperError);helper.kill('SIGKILL');},limit);
    try {
      helper.stdin.write(JSON.stringify({controller_pid:capability.controller_pid,controller_birth_ticks:capability.controller_birth_ticks,
        caller_pid:callerPid,client_pid:capability.client_pid,keeper_pid:opened.keeper_pid,init_pid:opened.init_pid,
        allocation_sequence:opened.allocation_sequence,worker_uid:opened.worker_uid,cleanup_budget_ms:opened.cleanup_budget_ms,
        original_max_end_ns:String(originalEnd)})+'\n');
      await Promise.race([ready,timedOut]);helper.stdin.end('KILL\n');await Promise.race([done,timedOut]);
      assert.equal(helperError,undefined,helperError?.message);assert.equal(exitCode,0,stderr);assert.equal(exitSignal,null);
      const value=JSON.parse(fs.readFileSync(observerOutput));
      assert.equal(value.status,'PASS_RETAINED_PIDFD_CRASH_OBSERVATION');assert.equal(value.actual_worker_observed,true);
      assert.equal(value.kill_sent_through_retained_pidfd,true);
      for(const key of ['native_terminal_proof','root_reaping_observed','cgroup_empty_observed'])assert.equal(value[key],false);
      assert.ok(value.identities.some(row=>row.role==='actual_private_worker'&&row.uid===opened.worker_uid));
      assert.ok(value.identities.some(row=>row.role==='storage_child'));
      assert.ok(value.identities.every(row=>row.pidfd_exit_observed===true&&BigInt(row.observed_ns)<BigInt(value.original_cleanup_endpoint_ns)));
      return {observation:value,raw_observer:path.basename(observerOutput),observer_sha256:sha(fs.readFileSync(observerOutput)),
        observer_script_sha256:sha(fs.readFileSync(observerFile))};
    } finally {
      clearTimeout(watchdog);if(!closed)helper.kill('SIGKILL');
      if(!closed){let timer;try{await Promise.race([done,new Promise(resolve=>{timer=setTimeout(resolve,2000);})]);}finally{clearTimeout(timer);}}
      if(!closed){helper.unref();for(const stream of helper.stdio)stream?.destroy?.();}
      fs.writeFileSync(path.join(evidence,name+'.observer.stdout.txt'),stdout);fs.writeFileSync(path.join(evidence,name+'.observer.stderr.txt'),stderr);
    }
  }
  async function invoke(name, body, { paired=false, workMs=30000, cancel=false, crash=false, expected='pass' }={}) {
    fs.writeFileSync(path.join(repo,'probe.js'),body);
    const q = request(name,workMs,paired), before = mono();
    assert.ok(cohortEnd-before > BigInt(workMs+17000)*1000000n, 'Not enough original cohort budget to admit another case');
    const row = { name, status:'FAIL', expected, request_sha256:finalization.digest(q), work_budget_ms:workMs,
      cleanup_budget_ms:15000, creator_owned_caller_exit:false, output_eof:false };
    if(crash)report.controller_crash=row;else report.cases.push(row);save();
    const child = spawn(process.execPath,[__filename,'--invoke',runtime],{ env,stdio:['pipe','pipe','pipe'] });
    let stdout=Buffer.alloc(0),stderr=Buffer.alloc(0),exited=false,closed=false,exitCode,signal,transportError=null,externalTimeout=false;
    child.stdout.on('data',part=>{stdout=Buffer.concat([stdout,part]);if(stdout.length>2*1024*1024){transportError=fail('qa_output_limit');child.kill('SIGKILL');}});
    child.stderr.on('data',part=>{stderr=Buffer.concat([stderr,part]);if(stderr.length>2*1024*1024){transportError=fail('qa_stderr_limit');child.kill('SIGKILL');}});
    child.once('error',error=>{transportError=error;});
    child.once('exit',(code,why)=>{exited=true;exitCode=code;signal=why;});
    const complete=new Promise(resolve=>child.once('close',()=>{closed=true;resolve();}));
    child.stdin.on('error',error=>{transportError ||= error;}); child.stdin.end(JSON.stringify(q));
    const externalMs=Math.min(workMs+17000,Number(cohortEnd-mono())/1e6);
    const watchdog=setTimeout(()=>{externalTimeout=true;child.kill('SIGKILL');},externalMs);
    let cancellation=null,crashObservation=null;
    try {
      if(cancel||crash) {
        const targetEnd=mono()+12000000000n;let observed;
        while(!closed && mono()<targetEnd) {
          observed=control.readStatus(context).attempt;
          if(observed?.claimed && observed.generation!==priorGeneration && observed.phase==='running' &&
             observed.containment?.backend==='linux_native_service') break;
          await delay(20);
        }
        assert.ok(observed?.claimed && observed.phase==='running' && observed.generation!==priorGeneration,
          'Public operation did not establish its actual native-bound running attempt');
        // Allow the fixed importer/authority to admit the deliberately silent
        // command; the returned native terminal must independently count it.
        await delay(2000);
        if(crash)crashObservation=await observeControllerCrash(name,observed,child.pid);
        else {
          const answer=control.requestCancel(context,{attempt_id:observed.attempt_id,generation:observed.generation,reason_code:'user_requested'});
          cancellation={attempt_id:observed.attempt_id,generation:observed.generation,result:answer};
        }
      }
      let closeTimer;
      try { await Promise.race([complete,new Promise((_,reject)=>{
        closeTimer=setTimeout(()=>reject(fail('qa_caller_close_unconfirmed')),externalMs+2000);
      })]); } finally { clearTimeout(closeTimer); }
      assert.equal(externalTimeout,false,'Outer caller watchdog is emergency containment, never native cleanup proof');
      assert.equal(transportError,null,transportError?.message);assert.equal(exitCode,0,stderr.toString());assert.equal(signal,null);
      const value=JSON.parse(stdout.toString('utf8'));assert.equal(value.schema_version,SCHEMA);assert.equal(value.uid,process.getuid());
      const attempt=control.readStatus(context).attempt;
      assert.ok(attempt && attempt.generation!==priorGeneration,JSON.stringify({public_result:value,attempt}));
      if(crash) {
        assert.equal(value.status,'threw');assert.equal(value.acceptances,undefined);assert.equal(value.records,undefined);
        assert.equal(value.error.code,'verification_linux_transport_failed');assert.equal(value.error.recovery_required,true);
        assert.equal(value.error.teardown.status,'unconfirmed');assert.equal(attempt.claimed,true);assert.equal(attempt.terminal,null);
        assert.notEqual(attempt.cleanup.status,'confirmed');
        assert.throws(()=>control.assertResourceAvailable(context),{code:'verification_recovery_required'});
        row.attempt_id=attempt.attempt_id;row.generation=attempt.generation;row.error=value.error;
        Object.assign(row,crashObservation,{no_acceptance_released:true,project_claim_fenced:true,
          original_native_terminal_proof:'NOT_AVAILABLE_AFTER_CONTROLLER_DEATH',
          status:'PASS_PUBLIC_CRASH_FENCE_AND_RETAINED_HANDLES',creator_owned_caller_exit:exited,output_eof:closed});
        persistControl(name,row,attempt);return;
      }
      assert.equal(attempt.claimed,false,JSON.stringify(attempt));
      assert.equal(attempt.cleanup.status,'confirmed'); const terminal=terminalFrom(attempt);
      assert.ok(terminal.commands>=1,'The native service must have admitted actual command work');
      assert.notEqual(terminal.authority_uid,terminal.worker_uid); assert.notEqual(terminal.authority_uid,process.getuid());assert.notEqual(terminal.worker_uid,process.getuid());
      row.attempt_id=attempt.attempt_id;row.generation=attempt.generation;row.terminal_outcome=attempt.terminal.outcome;
      row.native_terminal_sha256=terminal.proof_sha256;row.cancellation=cancellation;
      if(expected==='pass') {
        assert.equal(value.status,'returned',JSON.stringify(value));assert.equal(value.records.length,paired?2:1);
        assert.equal(value.acceptances.length,1);assert.equal(attempt.terminal.outcome,'passed');
        assert.equal(attempt.terminal.ack_sha256,finalization.digest(value.acceptances));
        const ids=value.records.map(item=>item.record.execution_id);
        const admitted=finalization.requireFinalizedExecutions(state,ids,value.acceptances);assert.equal(admitted.status,'accepted');
        assert.equal(admitted.execution_records.length,ids.length);
        const ack=value.acceptances[0], kvf=execution.readNativeRecord(state,ack.receipt_id.slice(4),'verification_finalizations');
        assert.ok(kvf);assert.equal(kvf.physical_sha256,ack.physical_sha256);service.validate(kvf.record);
        const kvfBytes=fs.readFileSync(kvf.path);assert.equal(sha(kvfBytes),kvf.physical_sha256);
        fs.writeFileSync(path.join(evidence,name+'.kvf.json'),kvfBytes);
        assert.equal(kvf.record.linux.terminal_reply.proof_sha256,terminal.proof_sha256);
        const printed=JSON.stringify({uid:terminal.worker_uid,euid:terminal.worker_uid,source_write_denied:true,state_write_denied:true})+'\n';
        assert.equal(value.records[0].record.stdout_sha256,sha(Buffer.from(printed)));
        assert.equal(value.records[0].record.stdout_bytes,Buffer.byteLength(printed));
        const savedExecutions=[];
        for(const [index,item] of value.records.entries()) {
          const loaded=execution.readExecutionRecord(state,item.record.execution_id);assert.ok(loaded);
          assert.equal(finalization.digest(loaded.record),finalization.digest(item.record));
          const bytes=fs.readFileSync(loaded.path), filename=name+'.kve-'+index+'.json';
          assert.equal(sha(bytes),loaded.physical_sha256);fs.writeFileSync(path.join(evidence,filename),bytes);
          savedExecutions.push({execution_id:item.record.execution_id,filename,physical_sha256:loaded.physical_sha256});
        }
        ownClosed(value.budget.storage_exit);ownClosed(value.budget.finalizer_exit);
        for(const key of ['exit_observed','close_observed','stdout_eof','stderr_eof'])assert.equal(value.budget.client_exit[key],true,key);
        assert.equal(value.budget.teardown.status,'completed');
        if(priorAcceptance)assert.throws(()=>finalization.requireFinalizedExecutions(state,ids,[priorAcceptance]),{code:'verification_finalization_required'});
        priorAcceptance=ack;
        row.execution_ids=ids;row.finalization_receipt_id=ack.receipt_id;row.finalization_physical_sha256=kvf.physical_sha256;
        row.raw_finalization=name+'.kvf.json';row.raw_executions=savedExecutions;
        row.acceptance_signature_verified=true;row.kve_kvf_physical_readback=true;row.older_acceptance_replay_rejected=report.cases.length>1;
      } else {
        assert.equal(value.status,'threw');assert.equal(value.acceptances,undefined);
        assert.equal(value.error.result_visibility,'ack_not_delivered');assert.equal(value.error.recovery_required,false,JSON.stringify(value));
        assert.equal(value.error.teardown.status,'completed',JSON.stringify(value));assert.equal(attempt.terminal.ack_sha256,null);
        assert.notEqual(attempt.terminal.outcome,'passed');
        if(expected==='nonzero')assert.equal(value.error.code,'verification_command_failed');
        if(expected==='timeout') {assert.equal(value.error.timed_out,true,JSON.stringify(value));assert.equal(attempt.terminal.outcome,'timed_out');}
        if(expected==='cancel') {assert.equal(value.error.code,'verification_cancelled');assert.equal(attempt.terminal.outcome,'cancelled');}
        const nativeClient=value.error.teardown.client_exit;
        assert.equal(nativeClient?.exit_observed,true);assert.equal(nativeClient?.close_observed,true);
        row.error=value.error;row.no_acceptance_released=true;
      }
      persistControl(name,row,attempt);
      priorGeneration=attempt.generation;row.status='PASS';row.creator_owned_caller_exit=exited;row.output_eof=closed;
    } catch(error) { row.status='FAIL';row.error=boundedError(error);throw error; }
    finally {
      clearTimeout(watchdog);if(!exited)child.kill('SIGKILL');
      if(!closed) {
        let timer;
        try { await Promise.race([complete,new Promise(resolve=>{timer=setTimeout(resolve,2000);})]); }
        finally {clearTimeout(timer);}
        if(!closed) {
          row.outer_cleanup_unconfirmed=true;child.unref();
          for(const stream of child.stdio)stream?.destroy?.();
        }
      }
      fs.writeFileSync(path.join(evidence,name+'.stdout.json'),stdout);fs.writeFileSync(path.join(evidence,name+'.stderr.txt'),stderr);
      row.elapsed_ms=ms(before);row.stdout_sha256=sha(stdout);row.stderr_sha256=sha(stderr);save();
    }
  }
  const positive="const fs=require('fs');let source=false,state=false;try{fs.writeFileSync('/source/probe.js','forbidden');}catch(e){source=['EROFS','EACCES','EPERM'].includes(e.code);}try{fs.writeFileSync('/state/forbidden','no');}catch(e){state=['EROFS','EACCES','EPERM'].includes(e.code);}if(!source||!state)throw Error('private UID isolation failed');const child=require('node:child_process').spawn(process.execPath,['-e','setInterval(()=>{},1000)'],{detached:true,stdio:['ignore',1,2]});child.unref();process.stdout.write(JSON.stringify({uid:process.getuid(),euid:process.geteuid(),source_write_denied:source,state_write_denied:state})+'\\n');\n";
  try {
    await invoke('positive',positive,{paired:true});
    await invoke('nonzero','process.stderr.write("expected-seven\\n");process.exit(7);\n',{expected:'nonzero'});
    await invoke('repeat-after-nonzero',positive);
    await invoke('timeout','setInterval(()=>{},1000);\n',{workMs:10000,expected:'timeout'});
    await invoke('repeat-after-timeout',positive);
    await invoke('cancel','setInterval(()=>{},1000);\n',{expected:'cancel',cancel:true});
    await invoke('repeat-after-cancel',positive);
    if(args['include-controller-crash'])await invoke('controller-crash','setInterval(()=>{},1000);\n',{crash:true,expected:'controller_crash'});
    report.status='PASS_LINUX_PUBLIC_PRODUCTION';report.normal_and_recovery_cases=report.cases.length;
  } finally {
    const after=sourceInventory();report.source_changes=[...new Set([...Object.keys(initialSource),...Object.keys(after)])]
      .filter(name=>initialSource[name]!==after[name]);
    if(report.source_changes.length)report.status='FAIL_SOURCE_CHANGED';
    save(); process.stdout.write(JSON.stringify({status:report.status,cases:report.cases.map(({name,status,elapsed_ms})=>({name,status,elapsed_ms})),output})+'\n');
  }
  assert.equal(report.status,'PASS_LINUX_PUBLIC_PRODUCTION');
}
