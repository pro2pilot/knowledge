'use strict';
// Pure, conservative evidence interpretation. Running this on Linux, including
// synthetic signed records, is a parser test and never Windows qualification.
const fs=require('node:fs'),path=require('node:path');
const T=require('./evidence-transport.cjs'),N=require('./native-probe.cjs');
const NAMES=[
  'Windows original CLI crash leaves independent B custody proof and a new Team Flow recovers',
  'Windows nested fixed Flow cancellation preserves a custodian outside every owned ancestor Job'
];
const INPUT='24df61b60ff43899a8e85884acf14bef6eb3a8c4a2537413033f5092b6965407';
const fail=code=>{throw Object.assign(new Error(code),{code});};
const GUARD_CHECKS=['allow_inside','reject_outside','reject_outside_force_missing','allow_inside_force_missing','reject_trailing_dot_alias',
  'reject_dotdot_alias','reject_junction','reject_junction_force_missing','outside_sentinel_unchanged'];
function utf8(bytes){return new TextDecoder('utf-8',{fatal:true}).decode(bytes);}
function ndjson(bytes){
  if(bytes.length>2097152)fail('QA_NDJSON_BOUND');const text=utf8(bytes);
  if(text&&!text.endsWith('\n'))fail('QA_NDJSON_TRUNCATED');
  const rows=text.trim()?text.trimEnd().split('\n').map(row=>T.parseStrictJSON(Buffer.from(row),786432)):[];
  if(rows.length>4096)fail('QA_NDJSON_BOUND');return rows;
}
function nativeBinding(value){return value?.schema_version==='knowledge-command-windows-native.v1'&&value.architecture==='arm64'&&
  value.source_sha256===N.EXPECTED.command.sourceSha&&value.binary_sha256===N.EXPECTED.command.sha&&
  value.assignment==='exact-root-once-no-breakaway.v1'&&value.watchdog==='native-pipe-process-handles.v1';}
function guardPreflight(data,identity){
  const lines=utf8(data.stdout).replace(/\r\n/g,'\n').split('\n');
  const markers=data.preflightRows.filter(r=>r.event==='preflight_worker_proof');
  if(markers.length!==1)fail('QA_PREFLIGHT_MARKER');const marker=markers[0];
  const loads=data.guardRows.filter(r=>r.event==='guard_loaded'&&r.pid===marker.pid);
  if(loads.length!==1)fail('QA_PREFLIGHT_WORKER_LOAD');const load=loads[0];
  if(marker.schema!=='knowledge-d5-guard-worker-proof.v1'||!/^child/.test(marker.worker_context||'')||marker.guard_version!==2||
    !GUARD_CHECKS.every(k=>marker.checks?.[k]===true)||load.version!==2||load.node_test_context!==true||load.recursive_only!==true||
    load.os_sandbox!==false||load.windows_reparse_inspector!==true||load.isMainThread!==true||load.threadId!==0||
    identity&&!(load.root_dev===identity.dev&&load.root_ino===identity.ino))fail('QA_PREFLIGHT_PROOF');
  const expected=['TAP version 13','ok 1 - D5 recursive guard is installed in the actual Windows test worker','1..1',
    '# tests 1','# suites 0','# pass 1','# fail 0','# cancelled 0','# skipped 0','# todo 0'];
  const allowedControls=new Set(expected.slice(0,3));
  if(!expected.every(value=>lines.filter(line=>line===value).length===1)||lines.some(line=>/^\s*(?:not ok\b|Bail out!)/.test(line))||
    lines.some(line=>line&&!/^[ #\t]/.test(line)&&!allowedControls.has(line))||
    lines.filter(line=>/^ok\b/.test(line)).length!==1)fail('QA_PREFLIGHT_TAP');
  return{schema:'knowledge-d5-preflight-acceptance.v1',status:'PASS_ACTUAL_WORKER_GUARD_BEFORE_PRODUCT',worker_pid:marker.pid,
    root_identity:{dev:load.root_dev,ino:load.root_ino},checks:marker.checks,scope:'recursive fs.rmSync only; not OS sandbox'};
}
function parseTap(bytes){
  if(bytes.length>2097152)fail('QA_TAP_BOUND');const text=utf8(bytes).replace(/\r\n/g,'\n'),lines=text.split('\n');
  const resultLines=lines.filter(x=>/^(?:not ok|ok) [1-9][0-9]* - /.test(x));
  const expected=NAMES.map((name,i)=>`ok ${i+1} - ${name}`);
  const counts={};
  for(const name of ['tests','suites','pass','fail','cancelled','skipped','todo']){
    const values=lines.filter(x=>new RegExp('^# '+name+' [0-9]+$').test(x));
    if(values.length!==1)fail('QA_TAP_SUMMARY');counts[name]=Number(values[0].split(' ').at(-1));
  }
  const allowedControls=new Set(['TAP version 13','1..2',...expected]);
  const complete=!lines.some(x=>/^\s*(?:not ok\b|Bail out!)/.test(x))&&
    !lines.some(x=>x&&!/^[ #\t]/.test(x)&&!allowedControls.has(x))&&lines.filter(x=>x==='TAP version 13').length===1&&lines.filter(x=>x==='1..2').length===1&&
    JSON.stringify(resultLines)===JSON.stringify(expected)&&counts.tests===2&&counts.suites===0&&counts.pass===2&&
    counts.fail===0&&counts.cancelled===0&&counts.skipped===0&&counts.todo===0;
  const diagnostics=[];
  for(const line of lines){if(line.startsWith('# {'))diagnostics.push(T.parseStrictJSON(Buffer.from(line.slice(2)),1048576));}
  let lossy=false;
  function examine(v){if(!v||typeof v!=='object')return;for(const[k,x]of Object.entries(v)){
    if(['oversized','truncated','fixture_retained','cleanup_not_claimed'].includes(k)&&x===true)lossy=true;
    if(k==='events'&&Array.isArray(x)&&x.length>=160)lossy=true;
    if(x&&typeof x==='object')examine(x);
  }}
  diagnostics.forEach(examine);
  const first=diagnostics.filter(v=>v.killed==='creator_owned_original_cli');
  const second=diagnostics.filter(v=>v.cancellation==='original_controller_abort_signal');
  const firstOk=first.length===1&&first[0].prior_scope_basis==='signed_terminal_receipt'&&first[0].new_flow_status==='ok'&&
    Number.isSafeInteger(first[0].output_bytes)&&first[0].output_bytes>=0&&first[0].output_bytes<1048576&&nativeBinding(first[0].native);
  const secondOk=second.length===1&&second[0].nested_fixed_cli===true&&second[0].prior_scope_basis==='signed_terminal_receipt'&&
    second[0].new_flow_status==='ok'&&nativeBinding(second[0].native);
  return {complete:complete&&firstOk&&secondOk&&!lossy,counts,diagnostic_recovery:[firstOk,secondOk],lossy_inner_diagnostic:lossy,
    stream_scope:'exact direct test-runner stdout; immutable inner CLI and trace collectors have their own documented caps'};
}
function analyze(data){
  const failures=[];let tap={complete:false,counts:{pass:0,fail:0,skipped:0,cancelled:0},diagnostic_recovery:[false,false]};
  try{tap=parseTap(data.stdout);}catch{failures.push('TAP_INCOMPLETE_OR_INVALID');}
  if(!tap.complete)failures.push('TWO_EXACT_TESTS_OR_RECOVERY_NOT_CONFIRMED');
  const o=data.observations||[],p=data.protocol;
  const installed=o.filter(r=>r.event==='observer_installed');
  const readonlyLoaded=o.filter(r=>r.event==='readonly_native_loaded');
  let sequenceOk=o.length>0&&o.every((r,i)=>r.schema==='knowledge-d5-observation.v1'&&r.sequence===i+1&&r.pid===o[0].pid);
  sequenceOk=sequenceOk&&installed.length===1&&installed[0].identity?.pid===installed[0].pid&&/^child/.test(installed[0].worker_context||'')&&
    installed[0].readonly_queries===true&&installed[0].original_returns_preserved===true&&installed[0].both_branches_extra_qa_observation===true&&
    installed[0].first_branch_existing_custody_trace===true&&
    readonlyLoaded.length===1&&nativeInfo(readonlyLoaded[0].info)&&
    readonlyLoaded[0].binary_sha256===N.EXPECTED.command.sha;
  if(!sequenceOk||o.some(r=>/overflow|capture_failed|closure_rejected/.test(r.event)))failures.push('OBSERVER_INCOMPLETE');
  const selected=o.filter(r=>r.event==='bound_scope_native_membership');
  const custody=[];
  if(selected.length!==2)failures.push('EXPECTED_OLD_SCOPES_MISSING');
  const uniqueSelected=new Set(selected.map(r=>r.scope?.descriptor?.scope_id)).size===selected.length&&new Set(selected.map(r=>r.origin)).size===selected.length;
  if(!uniqueSelected)failures.push('SELECTED_OLD_SCOPES_DUPLICATED');
  for(let i=0;i<selected.length;i++){
    const row=selected[i],scope=row.scope;let valid=false,ancestors=0,receiptValid=false,observedTerminal=null,graphSummary=null;
    try{
      const graph=analyzeGraph(row,installed[0]?.identity,p,i+1);
      graphSummary=graph;
      valid=row.test_boundary_ordinal===i+1&&readonlyLoaded[0]?.sequence<row.sequence&&
        row.selection==='exact immutable test boundScope callsite; selection is not native proof'&&graph.native_membership_complete;
      ancestors=graph.actual_owned_ancestors;
      const terminals=o.filter(v=>v.event==='original_query_scope_closure'&&v.sequence>row.sequence&&p.digest(v.scope)===p.digest(scope));
      for(const terminal of terminals){
        const v=terminal.observation;
        if(v?.status!=='completed'||v.basis!=='signed_terminal_receipt'||v.root_exited!==true||v.active_processes!==0||
            v.admission_sealed!==true||v.current_host_verified!==true)continue;
        for(const item of terminal.receipts||[]){
          if(item.validated===true&&p.validateTerminal(item.receipt,scope)&&item.role===item.receipt.body.role&&
            p.digest(item.receipt)===v.receipt_sha256){receiptValid=true;observedTerminal=terminal.sequence;}
        }
      }
    }catch{valid=false;}
    custody.push({test_ordinal:i+1,scope_id:scope?.descriptor?.scope_id||null,native_membership_complete:valid,
      actual_owned_ancestors:ancestors,validated_signed_terminal:receiptValid,terminal_sequence:observedTerminal,graph:graphSummary});
  }
  const nativeCustody=sequenceOk&&uniqueSelected&&selected.length===2&&custody.every(r=>r.native_membership_complete&&r.validated_signed_terminal);
  if(!nativeCustody)failures.push('EXACT_NATIVE_CUSTODY_AND_TERMINALS_UNCONFIRMED');
  const preflight=data.preflightRows||[],guardRows=data.guardRows||[],workerProof=preflight.filter(r=>r.event==='preflight_worker_proof');
  const guarded=pid=>guardRows.filter(r=>r.event==='guard_loaded'&&r.pid===pid&&r.version===2&&r.node_test_context===true&&
    r.recursive_only===true&&r.os_sandbox===false&&r.windows_reparse_inspector===true&&r.isMainThread===true&&r.threadId===0&&
    /^[0-9]+$/.test(r.root_dev)&&/^[1-9][0-9]*$/.test(r.root_ino));
  const guardOk=workerProof.length===1&&workerProof[0].schema==='knowledge-d5-guard-worker-proof.v1'&&/^child/.test(workerProof[0].worker_context||'')&&
    workerProof[0].guard_version===2&&GUARD_CHECKS.every(k=>workerProof[0].checks?.[k]===true)&&guarded(workerProof[0].pid).length===1&&
    installed.length===1&&guarded(installed[0].pid).length===1&&workerProof[0].pid!==installed[0].pid&&
    guarded(installed[0].pid)[0].root_dev===data.native?.product_temp?.dev&&guarded(installed[0].pid)[0].root_ino===data.native?.product_temp?.ino;
  const guard={schema:'knowledge-d5-guard-analysis.v1',status:guardOk?'PASS_ACTUAL_WORKER_GUARD':'UNCERTAIN',
    guard_worker_proof:guardOk,preflight:workerProof,product_worker:installed.map(v=>({pid:v.pid,worker_context:v.worker_context})),
    matching_loads:guardRows.filter(r=>r.node_test_context===true),scope:'fs.rmSync recursive only; no child coverage or OS sandbox claim'};
  if(!guardOk)failures.push('GUARD_ACTUAL_WORKER_PROOF_MISSING');
  const n=data.native;
  const sup=data.supervisor,ns=sup?.node_scope;
  const nativeOk=sup?.schema==='knowledge-d5-supervisor.v1'&&sup.scope==='WINDOWS_ARM_NODE24_TEAM_QA_ONLY'&&sup.os_arch==='Arm64'&&sup.pwsh_arch==='Arm64'&&
    sup.failure_code===null&&sup.source_after_failure_code===null&&ns?.platform==='win32'&&ns.architecture==='arm64'&&ns.version==='v24.22.1'&&Number.isSafeInteger(ns.napi)&&ns.napi>=8&&
    n?.status==='PASS_NATIVE_LOAD_SCOPE_ONLY'&&n.node?.platform==='win32'&&n.node.architecture==='arm64'&&
    n.node.version==='v24.22.1'&&Number.isSafeInteger(n.node.napi)&&n.node.napi===ns.napi&&n.node.napi>=8&&n.node.executable?.pe?.machine==='AA64'&&n.node.executable?.pe?.optional_header==='PE32+'&&
    nativeBinding(n.command_binding)&&nativeInfo(n.command_info)&&probeDisposition(n)&&
    n.lock_info?.schema_version==='knowledge-lock-publication-native.v1'&&n.lock_info.platform==='win32'&&n.lock_info.architecture==='arm64'&&
    n.lock_info.napi_version===8&&n.lock_info.source_sha256===N.EXPECTED.lock.sourceSha&&n.lock_info.lease_protocol==='windows-owner-event.v1';
  if(!nativeOk)failures.push('ACTUAL_ARM_NATIVE_LOAD_SCOPE_UNCONFIRMED');
  const sourceOk=['before','after'].every(name=>data[name]?.status==='PASS_SOURCE_TEST_INPUT_INTEGRITY'&&data[name].payloads===119&&
    data[name].members===120&&data[name].input_sha256===INPUT&&data[name].exact_internal_manifest===true)&&
    data.before?.mode==='extract'&&data.after?.mode==='verify-existing';
  if(!sourceOk)failures.push('SOURCE_PINS_BEFORE_AFTER_UNCONFIRMED');
  const product=data.supervisor?.product||{};
  if(product.started!==true||product.exited!==true||product.original_child_exit!==0||product.timed_out!==false||product.overflow!==false||
      product.stdout_eof!==true||product.stderr_eof!==true||product.pipe_failure!==false||product.kill_attempted!==false||
      product.kill_succeeded!==false||product.failure_code!==null||product.retained_handle_captured!==true||
      !Number.isSafeInteger(product.elapsed_ms)||product.elapsed_ms<0||product.elapsed_ms>650000||
      product.stdout_observed_bytes!==data.stdout.length||product.stderr_observed_bytes!==data.stderr.length)failures.push('CACHED_CHILD_EXIT_OR_COMPLETE_STREAMS_UNCONFIRMED');
  return {schema:'knowledge-d5-analysis.v1',status:failures.length?'UNCERTAIN':'PASS_OBSERVATION_CONTRACT',failures:[...new Set(failures)],product,
    tests:{expected:2,passed:tap.counts.pass||0,failed:(tap.counts.fail||0)+(tap.counts.cancelled||0),skipped:tap.counts.skipped||0},
    guard_worker_proof:guardOk,native_custody_complete:nativeCustody,native_arm_scope_verified:nativeOk,source_unchanged:sourceOk,
    tap,custody,guard,scope:'WINDOWS_ARM_NODE24_TEAM_QA_ONLY',root_review_required:true};
}
module.exports={NAMES,ndjson,parseTap,nativeBinding,nativeInfo,probeDisposition,guardPreflight,analyzeGraph,analyze};
if(require.main===module){
  try{
    if(process.argv.length===5&&process.argv[2]==='--guard-preflight'){
      const root=process.argv[3],owned=process.argv[4];
      if(process.platform!=='win32'||!path.isAbsolute(root)||!path.isAbsolute(owned))fail('QA_PREFLIGHT_SCOPE');
      const st=fs.lstatSync(owned,{bigint:true});if(!st.isDirectory()||st.isSymbolicLink())fail('QA_PREFLIGHT_ROOT');
      const f=name=>T.readBoundedFile(path.join(root,name),2097152);
      const value=guardPreflight({stdout:f('guard-preflight.stdout'),guardRows:ndjson(f('guard-proof.ndjson')),preflightRows:ndjson(f('preflight-proof.ndjson'))},
        {dev:String(st.dev),ino:String(st.ino)});
      process.stdout.write(JSON.stringify(value)+'\n');
      return;
    }
    if(process.argv.length!==4)fail('QA_ANALYSIS_ARGUMENTS');const root=process.argv[2],source=process.argv[3];
    if(!path.isAbsolute(root)||!path.isAbsolute(source))fail('QA_ANALYSIS_PATH');
    const file=name=>T.readBoundedFile(path.join(root,name),2097152),json=name=>T.parseStrictJSON(file(name),2097152);
    const data={stdout:file('product.stdout'),stderr:file('product.stderr'),observations:ndjson(file('observations.ndjson')),
      guardRows:ndjson(file('guard-proof.ndjson')),preflightRows:ndjson(file('preflight-proof.ndjson')),native:json('native.json'),
      before:json('source-before.json'),after:json('source-after.json'),supervisor:json('supervisor.json'),protocol:require(path.join(source,'tools/lib/command-windows-protocol.js'))};
    const result=analyze(data);fs.writeFileSync(path.join(root,'guard.json'),JSON.stringify(result.guard,null,2)+'\n',{flag:'wx'});
    fs.writeFileSync(path.join(root,'analysis.json'),JSON.stringify(result,null,2)+'\n',{flag:'wx'});
    process.stdout.write(JSON.stringify({status:result.status})+'\n');process.exitCode=result.status==='PASS_OBSERVATION_CONTRACT'?0:1;
  }catch{process.stderr.write('D5_ANALYSIS_FAILED\n');process.exitCode=1;}
}

// Full fixed-controller graph validation. Registry metadata only enumerates
// candidates; every membership predicate must be a successful native query.
function nativeInfo(value){return value?.schema_version==='knowledge-command-windows-native.v1'&&value.platform==='win32'&&value.architecture==='arm64'&&
  value.source_sha256===N.EXPECTED.command.sourceSha&&value.napi_version===8&&value.bootstrap==='job-list-at-birth.v1'&&
  value.assignment==='exact-root-once-no-breakaway.v1'&&value.watchdog==='native-pipe-process-handles.v1';}
function probeDisposition(n){
  const identity=v=>v&&typeof v.directory==='string'&&/^[A-Za-z]:\\/.test(v.directory)&&path.win32.normalize(v.directory)===v.directory&&
    !v.directory.slice(2).includes(':')&&!v.directory.split('\\').some(part=>/[ .]$/.test(part))&&
    /^(?:0|[1-9][0-9]{0,19})$/.test(v.dev)&&/^[1-9][0-9]{0,19}$/.test(v.ino);
  const a=n?.probe_temp,b=n?.product_temp,d=n?.snapshot_disposition,s=d?.snapshot;
  return identity(a)&&identity(b)&&a.directory!==b.directory&&path.win32.dirname(a.directory)===path.win32.dirname(b.directory)&&
    !(a.dev===b.dev&&a.ino===b.ino)&&d?.status==='RETAINED_LOADED_DLL_IN_SEPARATE_OWNED_PROBE_ROOT'&&d.cleanup_claimed===false&&
    s?.backend==='windows_job_object'&&s.platform==='win32'&&s.architecture==='arm64'&&s.source_sha256===N.EXPECTED.command.sourceSha&&
    s.binary_sha256===N.EXPECTED.command.sha&&s.binary_bytes===N.EXPECTED.command.bytes&&identity(s.snapshot)&&
    path.win32.dirname(s.snapshot.directory)===a.directory&&/^knowledge-command-native-[A-Za-z0-9]{6}$/.test(path.win32.basename(s.snapshot.directory))&&
    s.executable===path.win32.join(s.snapshot.directory,'command-windows-job.node');
}
function analyzeGraph(row,coordinator,p,ordinal){
  const same=(a,b)=>p.validIdentity(a)&&p.validIdentity(b)&&a.pid===b.pid&&a.birth_filetime===b.birth_filetime;
  const id=v=>`${v.pid}:${v.birth_filetime}`;
  const route=ordinal===1?['flow','guard','guard','guard']:ordinal===2?['guard','guard','cli','guard','guard','guard']:null;
  if(!route||!p.validIdentity(coordinator)||!/^[0-9a-f]{64}$/.test(row.origin||'')||!p.validateScope(row.scope)||!row.scope.descriptor.secondary||
    row.scope_sha256!==p.digest(row.scope)||!Array.isArray(row.registry)||row.registry.length!==route.length*2+(ordinal===1?3:5))fail('QA_GRAPH_REGISTRY_COUNT');
  const names=new Set(),decoded=[];let total=0;
  for(const item of row.registry){
    if(!item||Object.keys(item).sort().join(',')!=='base64,bytes,name,sha256'||typeof item.name!=='string'||names.has(item.name)||
      !new RegExp('^'+row.origin+'-(controller|spawn|ready)-[0-9a-f]{64}\\.json$').test(item.name)||
      !Number.isSafeInteger(item.bytes)||item.bytes<1||item.bytes>131072)fail('QA_GRAPH_REGISTRY_FILE');
    names.add(item.name);const raw=T.strictBase64(item.base64,131072,item.bytes);total+=raw.length;
    if(total>524288||T.sha256(raw)!==item.sha256||raw.at(-1)!==10)fail('QA_GRAPH_REGISTRY_PIN');
    const value=T.parseStrictJSON(raw,131072);
    if(value.schema!=='knowledge-d5-controller-registry.v1'||value.origin!==row.origin||!['controller','spawn','ready'].includes(value.kind)||
      !item.name.startsWith(row.origin+'-'+value.kind+'-')||!p.validIdentity(value.process))fail('QA_GRAPH_REGISTRY_SCHEMA');
    decoded.push({name:item.name,value});
  }
  if(JSON.stringify([...names])!==JSON.stringify([...names].sort()))fail('QA_GRAPH_REGISTRY_ORDER');
  const controllers=decoded.filter(r=>r.value.kind==='controller'),spawns=decoded.filter(r=>r.value.kind==='spawn'),readies=decoded.filter(r=>r.value.kind==='ready');
  if(controllers.length!==route.length||spawns.length!==route.length||readies.length!==(ordinal===1?3:5))fail('QA_GRAPH_ROLE_COUNT');
  if(new Set(controllers.map(r=>r.value.identity?.pid)).size!==controllers.length||controllers.some(r=>r.value.identity?.pid===coordinator.pid))fail('QA_GRAPH_IDENTITY_DUPLICATE');
  const controllerById=new Map(),spawnById=new Map();
  for(const record of controllers){const v=record.value;
    if(!same(v.process,v.identity)||!p.validIdentity(v.parent)||v.role!==v.entry||!['flow','guard','cli'].includes(v.entry)||
      !nativeInfo(v.native_info)||v.binary_sha256!==N.EXPECTED.command.sha||
      JSON.stringify(v.preload_order)!==JSON.stringify(ordinal===1?['immutable-custody-trace','qa-observer']:['qa-observer'])||
      v.admission!==(v.entry==='guard'?'after_native_permit_natural_command_worker_import':v.entry==='cli'?'after_cli_start_natural_command_runner_import':'ordinary_fixed_cli'))fail('QA_GRAPH_CONTROLLER');
    const key=id(v.identity);if(controllerById.has(key))fail('QA_GRAPH_CONTROLLER_DUPLICATE');controllerById.set(key,v);
  }
  for(const record of spawns){const v=record.value;
    if(!same(v.process,v.parent)||!p.validIdentity(v.child)||v.creator_owned_child_object!==true||v.observer_inserted_after_existing_preloads!==true||
      !Array.isArray(v.preloads_seen_at_interceptor)||v.preloads_seen_at_interceptor.some(x=>!['immutable-custody-trace','qa-observer'].includes(x)))fail('QA_GRAPH_SPAWN');
    const child=controllerById.get(id(v.child));
    if(!child||!same(child.parent,v.parent)||child.entry!==v.entry||v.role!==(same(v.parent,coordinator)?'test-worker':controllerById.get(id(v.parent))?.entry))fail('QA_GRAPH_PROPAGATION');
    const key=id(v.child);if(spawnById.has(key))fail('QA_GRAPH_SPAWN_DUPLICATE');spawnById.set(key,v);
  }
  const chain=[];let parent=coordinator;
  for(const kind of route){
    const children=[...controllerById.values()].filter(v=>same(v.parent,parent));
    if(children.length!==1||children[0].entry!==kind)fail('QA_GRAPH_FIXED_ROUTE');chain.push(children[0]);parent=children[0].identity;
  }
  if([...controllerById.values()].some(v=>same(v.parent,parent)))fail('QA_GRAPH_EXTRA_DESCENDANT');
  if(!same(row.scope.descriptor.root,chain.at(-2).identity))fail('QA_GRAPH_SELECTED_ROOT');
  const readyById=new Map(),readyByRoot=new Map();
  for(const record of readies){const v=record.value,d=v.scope?.descriptor;
    if(!p.validateScope(v.scope)||!nativeBinding(d.native)||!same(v.creator,v.process)||!same(v.creator,d.controller)||!same(v.root_spawn,d.root)||
      v.creator_owned_child_object_matched!==true||record.name!==row.origin+'-ready-'+d.scope_id+'.json')fail('QA_GRAPH_READY');
    const spawn=spawnById.get(id(d.root));
    if(!spawn||spawn.entry!=='guard'||!same(spawn.parent,v.creator)||v.role!==(same(v.creator,coordinator)?'test-worker':controllerById.get(id(v.creator))?.entry))fail('QA_GRAPH_READY_CHILD_OBJECT');
    if(readyById.has(d.scope_id)||readyByRoot.has(id(d.root)))fail('QA_GRAPH_READY_DUPLICATE');readyById.set(d.scope_id,record);readyByRoot.set(id(d.root),record);
  }
  const guards=chain.filter(v=>v.entry==='guard');if(guards.some(v=>!readyByRoot.has(id(v.identity))))fail('QA_GRAPH_UNREGISTERED_GUARD');
  const selected=readyById.get(row.scope.descriptor.scope_id);
  if(!selected||p.digest(selected.value.scope)!==p.digest(row.scope))fail('QA_GRAPH_SELECTED_UNREGISTERED');
  if(!Array.isArray(row.owned_jobs_examined)||row.owned_jobs_examined.length!==readies.length)fail('QA_GRAPH_MEMBERSHIP_INCOMPLETE');
  if(row.held_matrix?.schema!=='knowledge-d5-held-matrix-result.v1'||row.held_matrix.close_all!==true||row.held_matrix.closed_count!==4*readies.length||
     !Array.isArray(row.held_matrix.rows)||row.held_matrix.rows.length!==readies.length)fail('QA_HELD_MATRIX_INCOMPLETE');
  const heldById=new Map();
  for(const held of row.held_matrix.rows){
    if(!held||typeof held.scope_id!=='string'||heldById.has(held.scope_id)||held.registered_root!==true||held.anchor_after!==true||
       held.secondary!==false||typeof held.selected_root!=='boolean')fail('QA_HELD_MATRIX_UNCONFIRMED');
    heldById.set(held.scope_id,held);
  }
  const seen=new Set();let ancestors=0;
  for(const observation of row.owned_jobs_examined){
    const d=observation.scope?.descriptor,record=readyById.get(d?.scope_id);
    if(!record||seen.has(d.scope_id)||observation.registry_name!==record.name||p.digest(observation.scope)!==p.digest(record.value.scope))fail('QA_GRAPH_MEMBERSHIP_MAPPING');seen.add(d.scope_id);
    for(const field of ['registered_root','selected_root','secondary'])if(observation[field]?.confirmed!==true||typeof observation[field].member!=='boolean')fail('QA_GRAPH_MEMBERSHIP_UNKNOWN');
    if(observation.registered_root.member!==true||observation.secondary.member!==false)fail('QA_GRAPH_NATIVE_CUSTODY');
    const index=chain.findIndex(v=>same(v.identity,d.root)),isExpectedMember=index<=chain.length-2;
    if(index<0||observation.selected_root.member!==isExpectedMember)fail('QA_GRAPH_NATIVE_LINEAGE');
    const held=heldById.get(d.scope_id);
    if(!held||held.selected_root!==isExpectedMember||held.registered_root!==observation.registered_root.member||
       held.secondary!==observation.secondary.member||held.selected_root!==observation.selected_root.member)fail('QA_HELD_MATRIX_MISMATCH');
    if(d.scope_id!==row.scope.descriptor.scope_id&&observation.selected_root.member)ancestors++;
  }
  if(ancestors!==(ordinal===1?1:3))fail('QA_GRAPH_ANCESTOR_COUNT');
  return{native_membership_complete:true,actual_owned_ancestors:ancestors,registered_named_jobs:readies.length,registered_controllers:controllers.length,
    origin:row.origin,route,scope_id:row.scope.descriptor.scope_id};
}
