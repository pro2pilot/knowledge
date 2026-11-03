'use strict';
// QA observer for exactly three immutable controller entrypoints. No
// NODE_OPTIONS/deletion-guard propagation. Guard/CLI preloads install only
// builtin hooks; registry/native work waits for natural admitted imports.
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto'),Module=require('node:module'),cp=require('node:child_process');
const source=process.env.KNOWLEDGE_QA_SOURCE_ROOT,privateRoot=process.env.KNOWLEDGE_QA_PRIVATE_ROOT;
const testPath=path.join(source||'','tests/reliability-windows-team-crash.test.js');
const flowPath=path.join(source||'','tools/flow.js'),guardPath=path.join(source||'','tools/lib/command-windows-guard.js');
const cliPath=path.join(source||'','tools/lib/command-cli-worker.js'),workerPath=path.join(source||'','tools/lib/command-worker.js');
const runnerPath=path.join(source||'','tools/lib/command-runner.js'),scopePath=path.join(source||'','tools/lib/command-windows-scope.js');
const proofPath=path.join(source||'','tools/lib/command-scope-proof.js');
const tracePath=path.join(source||'','tests/helpers/reliability-windows-custody-trace.cjs');
function classifyRole(sourceRoot,entry,nodeTestContext,p=path){
  if(entry===p.join(sourceRoot||'','tests/reliability-windows-team-crash.test.js')&&/^child/.test(nodeTestContext||''))return'test-worker';
  for(const[kind,file]of [['flow','tools/flow.js'],['guard','tools/lib/command-windows-guard.js'],['cli','tools/lib/command-cli-worker.js']])
    if(entry===p.join(sourceRoot||'',file))return kind;
  return null;
}
function parseControllerArguments(args,sourceRoot,observerFile,p=path){
  if(!Array.isArray(args)||args.some(v=>typeof v!=='string'))return null;
  const trace=p.join(sourceRoot,'tests/helpers/reliability-windows-custody-trace.cjs');
  const fixed=['tools/flow.js','tools/lib/command-windows-guard.js','tools/lib/command-cli-worker.js'].map(v=>p.join(sourceRoot,v));
  let at=0;const preloads=[];
  while(args[at]==='--require'||args[at]==='-r'){
    const preload=args[at+1];if(![trace,observerFile].includes(preload)||preloads.includes(preload))throw new Error('qa_preload_sequence');
    preloads.push(preload);at+=2;
  }
  if(preloads.includes(trace)&&preloads.includes(observerFile)&&preloads.indexOf(trace)>preloads.indexOf(observerFile))throw new Error('qa_preload_order');
  if(!args[at]||args[at].startsWith('-')){if(args.some(v=>fixed.includes(v)))throw new Error('qa_controller_node_flags');return null;}
  const entry=args[at],target=classifyRole(sourceRoot,entry,null,p);
  return{entry,at,preloads,target:['flow','guard','cli'].includes(target)?target:null};
}
module.exports={classifyRole,parseControllerArguments};
const entry=process.argv[1],role=classifyRole(source,entry,process.env.NODE_TEST_CONTEXT),isTest=role==='test-worker';
if(role)install();
function install(){
  const registry=process.env.KNOWLEDGE_QA_OBSERVER_REGISTRY,observationFile=process.env.KNOWLEDGE_QA_OBSERVER_FILE;
  const inheritedOrigin=process.env.KNOWLEDGE_QA_OBSERVER_ORIGIN;
  if(process.platform!=='win32'||process.arch!=='arm64'||process.version!=='v24.22.1'||!path.isAbsolute(source||'')||!path.isAbsolute(privateRoot||'')||
    registry!==path.join(privateRoot,'observer-registry')||observationFile!==path.join(privateRoot,'observations.ndjson')||
    !isTest&&!/^[0-9a-f]{64}$/.test(inheritedOrigin||''))throw new Error('qa_observer_scope');
  const initialLoad=Module._load,initialSpawn=cp.spawn,children=new WeakMap(),selected=new Set();
  let admitted=isTest||role==='flow',initialized=false,initializing=false,native,protocol,transport,who,nativeInfo,sequence=0,bytes=0,boundaryOrdinal=0;
  let obsIdentity,registryIdentity,failed=false,preAdmissionViolation=false,observationStopped=false;
  const same=(a,b)=>a?.pid===b?.pid&&a?.birth_filetime===b?.birth_filetime;
  function regularDirectory(file){const st=fs.lstatSync(file,{bigint:true});if(!st.isDirectory()||st.isSymbolicLink()||fs.realpathSync.native(file).toLowerCase()!==file.toLowerCase())throw new Error('qa_observer_directory');return st;}
  function sameRegistry(){const st=regularDirectory(registry);if(st.dev!==registryIdentity.dev||st.ino!==registryIdentity.ino)throw new Error('qa_registry_identity');}
  function event(event,details={}){
    if(!isTest||!initialized||observationStopped)return;
    try{
      const st=fs.lstatSync(observationFile,{bigint:true});
      if(!st.isFile()||st.isSymbolicLink()||st.nlink!==1n||st.dev!==obsIdentity.dev||st.ino!==obsIdentity.ino)throw new Error('qa_observation_identity');
      let text=JSON.stringify({schema:'knowledge-d5-observation.v1',sequence:++sequence,pid:process.pid,event,...details})+'\n';
      if(Buffer.byteLength(text)>786432||bytes+Buffer.byteLength(text)>1900000){text=JSON.stringify({schema:'knowledge-d5-observation.v1',sequence,pid:process.pid,event:'observer_overflow'})+'\n';failed=true;observationStopped=true;}
      fs.appendFileSync(observationFile,text);bytes+=Buffer.byteLength(text);
    }catch{failed=true;observationStopped=true;process.exitCode=1;}
  }
  function publish(kind,origin,details){
    sameRegistry();const nonce=kind==='ready'?details.scope.descriptor.scope_id:crypto.randomBytes(32).toString('hex');
    const name=`${origin}-${kind}-${nonce}.json`,temp=path.join(registry,`${origin}-${kind}-${nonce}.pending`),target=path.join(registry,name);
    const body=Buffer.from(JSON.stringify({schema:'knowledge-d5-controller-registry.v1',kind,origin,process:who,role,...details})+'\n');
    if(body.length>131072||fs.readdirSync(registry).length>=1024)throw new Error('qa_registry_bound');
    let fd;try{
      fd=fs.openSync(temp,fs.constants.O_CREAT|fs.constants.O_EXCL|fs.constants.O_WRONLY|(fs.constants.O_NOFOLLOW||0),0o600);
      fs.writeFileSync(fd,body);fs.fsyncSync(fd);fs.closeSync(fd);fd=undefined;sameRegistry();
      // Exclusive link publishes complete bytes; the known own temporary link
      // is then unlinked. All ancestor ready publications precede permit.
      fs.linkSync(temp,target);fs.unlinkSync(temp);sameRegistry();return name;
    }finally{if(fd!==undefined)fs.closeSync(fd);}
  }
  function initialize(){
    if(initialized)return true;if(!admitted||initializing)return false;initializing=true;
    try{
      transport=require('./evidence-transport.cjs');
      protocol=initialLoad.call(Module,path.join(source,'tools/lib/command-windows-protocol.js'),module,false);
      const artifacts=require('./native-probe.cjs').validateArtifacts(source);
      native=initialLoad.call(Module,path.join(source,'tools/lib/native/win32-arm64/command-windows-job.node'),module,false);nativeInfo=native.info();
      if(nativeInfo.schema_version!=='knowledge-command-windows-native.v1'||nativeInfo.platform!=='win32'||nativeInfo.architecture!=='arm64'||
        nativeInfo.source_sha256!==artifacts.command.manifest.source_sha256||nativeInfo.napi_version!==8||nativeInfo.bootstrap!=='job-list-at-birth.v1')throw new Error('qa_observer_native');
      who=native.currentIdentity();if(!protocol.validIdentity(who))throw new Error('qa_observer_identity');
      regularDirectory(privateRoot);registryIdentity=regularDirectory(registry);
      if(isTest){obsIdentity=fs.lstatSync(observationFile,{bigint:true});if(!obsIdentity.isFile()||obsIdentity.isSymbolicLink()||obsIdentity.nlink!==1n||obsIdentity.size!==0n)throw new Error('qa_observation_file');}
      initialized=true;
      if(isTest){event('observer_installed',{identity:who,worker_context:process.env.NODE_TEST_CONTEXT,readonly_queries:true,original_returns_preserved:true,
        first_branch_existing_custody_trace:true,both_branches_extra_qa_observation:true,controller_propagation:'exact fixed flow/guard/cli entries with lazy admission'});
        event('readonly_native_loaded',{info:nativeInfo,binary_sha256:artifacts.command.manifest.binary_sha256});}
      else{
        const parent=native.processIdentity(process.ppid);
        if(parent.exited||!protocol.validIdentity({pid:parent.pid,birth_filetime:parent.birth_filetime}))throw new Error('qa_observer_parent');
        const preloadOrder=[];
        for(let i=0;i<process.execArgv.length;i+=2){
          if(!['--require','-r'].includes(process.execArgv[i])||![tracePath,__filename].includes(process.execArgv[i+1]))throw new Error('qa_controller_exec_argv');
          preloadOrder.push(process.execArgv[i+1]===tracePath?'immutable-custody-trace':'qa-observer');
        }
        publish('controller',inheritedOrigin,{entry:role,identity:who,parent:{pid:parent.pid,birth_filetime:parent.birth_filetime},preload_order:preloadOrder,
          admission:role==='guard'?'after_native_permit_natural_command_worker_import':role==='cli'?'after_cli_start_natural_command_runner_import':'ordinary_fixed_cli',
          native_info:nativeInfo,binary_sha256:artifacts.command.manifest.binary_sha256});
      }
      if(preAdmissionViolation)throw new Error('qa_pre_admission_spawn');return true;
    }catch{
      failed=true;if(initialized){try{publish('failure',isTest?'coordinator':inheritedOrigin,{code:'qa_observer_initialization_failed'});}catch{}event('observer_capture_failed');}return false;
    }finally{initializing=false;}
  }
  function problem(code,origin){
    failed=true;if(!admitted){preAdmissionViolation=true;return;}
    if(initialize()){try{publish('failure',origin||inheritedOrigin||'coordinator',{code});}catch{}event('observer_capture_failed',{code});}
  }
  function parseEntry(args){
    return parseControllerArguments(args,source,__filename);
  }
  cp.spawn=function(command,args,options){
    if(command!==process.execPath)return initialSpawn.apply(this,arguments);
    let parsed;try{parsed=parseEntry(args);}catch{problem('qa_preload_sequence');return initialSpawn.apply(this,arguments);}
    if(!parsed)return initialSpawn.apply(this,arguments);
    const target=parsed.target;
    if(!target)return initialSpawn.apply(this,arguments);
    if(!admitted){preAdmissionViolation=true;return initialSpawn.apply(this,arguments);}
    const origin=isTest?crypto.randomBytes(32).toString('hex'):inheritedOrigin;
    const instrumented=args.slice();if(!parsed.preloads.includes(__filename))instrumented.splice(parsed.at,0,'--require',__filename);
    const controlled={...(options||{}),env:{...(options?.env||process.env),KNOWLEDGE_QA_OBSERVER_ORIGIN:origin,
      KNOWLEDGE_QA_OBSERVER_REGISTRY:registry,KNOWLEDGE_QA_OBSERVER_FILE:observationFile,KNOWLEDGE_QA_SOURCE_ROOT:source,KNOWLEDGE_QA_PRIVATE_ROOT:privateRoot}};
    const child=initialSpawn.call(this,command,instrumented,controlled);
    try{
      if(!initialize()||!child.pid)throw new Error('qa_spawn_unconfirmed');
      const identity=native.processIdentity(child.pid);
      if(identity.exited||!protocol.validIdentity({pid:identity.pid,birth_filetime:identity.birth_filetime}))throw new Error('qa_spawn_birth');
      const record={origin,identity:{pid:identity.pid,birth_filetime:identity.birth_filetime},entry:target};children.set(child,record);
      publish('spawn',origin,{parent:who,child:record.identity,entry:target,creator_owned_child_object:true,
        preloads_seen_at_interceptor:parsed.preloads.map(p=>p===tracePath?'immutable-custody-trace':'qa-observer'),observer_inserted_after_existing_preloads:true,
        observation:'native exact birth checked while creator-owned ChildProcess retained; PID alone is not custody proof'});
    }catch{problem('qa_controller_propagation_failed',origin);}
    return child;
  };
  function membership(job,identity){try{const member=native.memberOf(job,identity);return{confirmed:typeof member==='boolean',member};}
    catch(error){return{confirmed:false,code:/^[a-zA-Z0-9_]{1,96}$/.test(error.code||'')?error.code:'qa_membership_unconfirmed'};}}
  function heldMatrix(jobs,scope){
    const exe=process.env.KNOWLEDGE_QA_PWSH_EXE,script=path.join(__dirname,'job-matrix.ps1');
    if(!path.isAbsolute(exe||'')||!path.isAbsolute(script)||jobs.length<1||jobs.length>5)throw new Error('qa_held_matrix_input');
    const request={schema:'knowledge-d5-held-matrix-request.v1',jobs:jobs.map(r=>({scope_id:r.value.scope.descriptor.scope_id,
      job:r.value.scope.descriptor.job_name,root:r.value.scope.descriptor.root,selected:scope.descriptor.root,secondary:scope.descriptor.secondary.identity}))};
    const input=JSON.stringify(request);if(Buffer.byteLength(input)>65536)throw new Error('qa_held_matrix_input');
    const env={};for(const key of ['SystemRoot','WINDIR','SystemDrive','TEMP','TMP','USERPROFILE','APPDATA','LOCALAPPDATA','PATH'])if(process.env[key])env[key]=process.env[key];
    const run=cp.spawnSync(exe,['-NoProfile','-NonInteractive','-File',script],{input,encoding:'utf8',env,windowsHide:true,timeout:10000,maxBuffer:131072});
    if(run.error||run.status!==0||run.signal||typeof run.stdout!=='string'||Buffer.byteLength(run.stdout)>131072||run.stderr){
      const detail=typeof run.stderr==='string'?run.stderr.slice(0,2048):'';
      event('held_matrix_helper_failed',{status:run.status,signal:run.signal||null,error_code:run.error?.code||null,stderr:detail});
      throw new Error('qa_held_matrix_process_unconfirmed');
    }
    const result=transport.parseStrictJSON(Buffer.from(run.stdout.trim()),131072);
    if(result.schema!=='knowledge-d5-held-matrix-result.v1'||result.close_all!==true||result.closed_count!==4*jobs.length||!Array.isArray(result.rows)||result.rows.length!==jobs.length)throw new Error('qa_held_matrix_receipt');
    return result;
  }
  function registrySnapshot(scope){
    sameRegistry();const names=fs.readdirSync(registry).sort();if(names.length>1024)throw new Error('qa_registry_incomplete');
    if(names.some(n=>!/^(?:[0-9a-f]{64}|coordinator)-(?:controller|spawn|ready|closed|failure)-[0-9a-f]{64}\.(?:json|pending)$/.test(n)))throw new Error('qa_registry_name');
    const selectedNames=names.filter(n=>n.endsWith('-ready-'+scope.descriptor.scope_id+'.json'));
    if(selectedNames.length!==1)throw new Error('qa_selected_scope_unregistered');
    const origin=selectedNames[0].slice(0,64),currentNames=names.filter(n=>n.startsWith(origin+'-'));
    // Earlier killed origins may retain incomplete own writes. They cannot
    // poison or prove this origin's independently queried native graph.
    if(!/^[0-9a-f]{64}$/.test(origin)||currentNames.some(n=>n.endsWith('.pending')))throw new Error('qa_registry_incomplete');
    let total=0;const decoded=[];
    for(const name of currentNames){
      const raw=transport.readBoundedFile(path.join(registry,name),131072);total+=raw.length;if(total>2097152)throw new Error('qa_registry_total');
      const value=transport.parseStrictJSON(raw,131072);if(value.schema!=='knowledge-d5-controller-registry.v1'||value.origin!==origin)throw new Error('qa_registry_schema');
      decoded.push({name,bytes:raw.length,sha256:transport.sha256(raw),base64:raw.toString('base64'),value});
    }
    const selectedReady=decoded.filter(v=>v.value.kind==='ready'&&v.value.scope?.descriptor?.scope_id===scope.descriptor.scope_id);
    if(selectedReady.length!==1||protocol.digest(selectedReady[0].value.scope)!==protocol.digest(scope))throw new Error('qa_selected_scope_unregistered');
    const rows=decoded;
    if(rows.some(v=>v.value.kind==='failure'||v.value.kind==='closed'))throw new Error('qa_origin_not_continuously_live');
    return{origin,rows};
  }
  function capture(scope){
    if(!initialize()||!protocol.validateScope(scope)||!scope.descriptor.secondary||selected.has(scope.descriptor.scope_id))return;
    const prefix='at boundScope ('+testPath+':';if(!String(new Error().stack).split('\n').some(line=>line.trim().startsWith(prefix)))return;
    selected.add(scope.descriptor.scope_id);
    const snapshot=registrySnapshot(scope),jobs=snapshot.rows.filter(r=>r.value.kind==='ready');
    const held=heldMatrix(jobs,scope);
    const examined=jobs.map(r=>({scope:r.value.scope,registry_name:r.name,
      registered_root:membership(r.value.scope.descriptor.job_name,r.value.scope.descriptor.root),
      selected_root:membership(r.value.scope.descriptor.job_name,scope.descriptor.root),
      secondary:membership(r.value.scope.descriptor.job_name,scope.descriptor.secondary.identity)}));
    event('bound_scope_native_membership',{scope,scope_sha256:protocol.digest(scope),test_boundary_ordinal:++boundaryOrdinal,
      selection:'exact immutable test boundScope callsite; selection is not native proof',origin:snapshot.origin,
      registry:snapshot.rows.map(({value,...raw})=>raw),owned_jobs_examined:examined,held_matrix:held,
      enumerator:'all same-origin named product command Jobs across fixed controllers; unnamed holder-only and ambient Jobs excluded by source',
      basis:'actual native.memberOf exact-birth calls before immutable crash/cancel; registry only enumerates candidates'});
  }
  function patchScope(api){
    if(api.__d5_observed)return;Object.defineProperty(api,'__d5_observed',{value:true});const spawn=api.spawnWindowsContainedWorker;
    api.spawnWindowsContainedWorker=function(...args){
      const value=spawn.apply(this,args);let scope,origin;
      value.job.ready.then(descriptor=>{
        try{
          if(!initialize())throw new Error('qa_ready_init');scope=protocol.commandScope(descriptor);
          const child=children.get(value.worker);
          if(!child||!same(child.identity,descriptor.root)||!same(who,descriptor.controller))throw new Error('qa_ready_creator_birth');
          origin=child.origin;if(!isTest&&origin!==inheritedOrigin)throw new Error('qa_ready_origin');
          publish('ready',origin,{scope,creator:who,root_spawn:child.identity,creator_owned_child_object_matched:true});
        }catch{problem('qa_ready_registry_failed',origin);}
      },()=>{});
      for(const name of ['close','drain']){const close=value.job[name];value.job[name]=function(...params){
        const promise=close.apply(this,params);Promise.resolve(promise).then(result=>{
          if(scope&&origin){try{publish('closed',origin,{scope_id:scope.descriptor.scope_id,result,method:name});}catch{problem('qa_close_registry_failed',origin);}}
        },()=>problem('qa_close_registry_rejected',origin));return promise;
      };}
      return value;
    };
  }
  function patchProof(api){
    if(!isTest||api.__d5_observed)return;Object.defineProperty(api,'__d5_observed',{value:true});
    const validate=api.validateExecutionScope,query=api.queryScopeClosure;
    api.validateExecutionScope=function(...args){const value=validate.apply(this,args);if(value===true){try{capture(args[0]);}catch{problem('qa_selected_graph_capture_failed');throw new Error('qa_selected_graph_capture_failed');}}return value;};
    api.queryScopeClosure=function(...args){
      const value=query.apply(this,args),scope=args[0];
      if(initialized&&selected.has(scope?.descriptor?.scope_id)){
        try{
          const receipts=[];
          if(value.status==='completed'&&value.basis==='signed_terminal_receipt'){
            const store=initialLoad.call(Module,path.join(source,'tools/lib/command-windows-receipts.js'),module,false);
            for(const role of ['primary','secondary']){try{const receipt=store.readRole(scope,role);receipts.push({role,receipt,validated:protocol.validateTerminal(receipt,scope)});}
              catch(error){receipts.push({role,available:false,code:/^[a-zA-Z0-9_]{1,96}$/.test(error.code||'')?error.code:'qa_receipt_unavailable'});}}
          }
          event('original_query_scope_closure',{scope,observation:value,receipts});
        }catch{problem('qa_selected_receipt_capture_failed');}
      }return value;
    };
  }
  Module._load=function(request,parent,isMain){
    let resolved;try{resolved=Module._resolveFilename(request,parent,isMain);}catch{return initialLoad.apply(this,arguments);}
    const admission=!admitted&&(role==='guard'&&resolved===workerPath||role==='cli'&&resolved===runnerPath);
    if(admission)admitted=true;
    const value=initialLoad.apply(this,arguments);
    if(resolved===scopePath)patchScope(value);if(resolved===proofPath)patchProof(value);
    if(admission)initialize();return value;
  };
  // Existing first-branch trace preload stays before this observer in argv.
  // Its historical pre-admission effects are not removed or reclassified.
  if(isTest||role==='flow')initialize();
}
