'use strict';

// This module never accepts a caller-supplied PID, native proof, or force flag.
// Native inputs come exclusively from the durable attempt which owns the root.
const crypto=require('crypto');
const control=require('./verification-control');
const {copyInertData}=require('./inert-data');
const hash=value=>crypto.createHash('sha256').update(value).digest('hex');
function fail(code) {throw Object.assign(new Error(code),{code});}
function requireThat(condition,code='verification_recovery_proof_invalid') {if(!condition)fail(code);}
function backendFor(attempt) {
  const backend=attempt?.containment?.backend;
  if(backend==='linux_pid_namespace' && process.platform==='linux') return require('./verification-linux-namespace');
  if(backend==='windows_job_object' && process.platform==='win32') return require('./verification-windows-recovery');
  if(backend==='darwin_private_ruid' && process.platform==='darwin') return require('./verification-darwin-control');
  fail(backend?'verification_native_recovery_unavailable':'verification_recovery_descriptor_missing');
}
function namespaceFinality(proof,attempt) {
  if(proof.namespace_drained!==true || typeof proof.init_reaped!=='boolean' ||
    ['init_exit_inferred','init_release_inferred'].some(key=>Object.hasOwn(proof,key) && typeof proof[key]!=='boolean')) return false;
  if(proof.init_exit_observed===true) {
    if(proof.init_exit_inferred===true || proof.init_release_inferred===true) return false;
    return proof.init_reaped===true || proof.init_exit_basis==='linux_pidfd_exit' && proof.init_reap_basis==='kernel_namespace_init_final_exit';
  }
  return attempt.recovery?.status==='active' && proof.init_exit_observed===false && proof.init_exit_inferred===true && proof.init_reaped===false && proof.init_release_inferred===true &&
    ['linux_boot_birth_absent','linux_boot_birth_replaced'].includes(proof.init_exit_basis) && proof.init_reap_basis==='kernel_namespace_init_final_exit';
}
function bindProof(attempt,nativeProof) {
  const c=attempt.containment,proof=copyInertData(nativeProof);
  requireThat(c && hash(JSON.stringify(c.descriptor))===c.descriptor_sha256,'verification_process_identity_mismatch');
  requireThat(proof && proof.descriptor_sha256===c.descriptor_sha256,'verification_process_identity_mismatch');
  if(c.backend==='darwin_private_ruid') {
    const bridge=require('./verification-darwin-control');
    requireThat(bridge.validateAttemptBinding(attempt) && proof.proof_kind==='recovery_observation' &&
      bridge.validateProof(proof,c.descriptor,{allowRecovery:true}));
    const result={...proof,attempt_id:attempt.attempt_id,generation:attempt.generation,
      process_exits:attempt.processes.filter(p=>!p.exit_observed).map(p=>({spawn_id:p.spawn_id,pid:p.pid,
        os_creation_time:null,process_nonce:p.process_nonce,method:'darwin_registered_authority_exit'})),
      native_return:copyInertData(nativeProof)};
    delete result.evidence_sha256;
    result.evidence_sha256=hash(JSON.stringify(result));return result;
  }
  requireThat(proof && proof.status==='completed' && proof.method===c.backend && proof.active_processes===0 &&
    proof.keeper_exited===true && proof.worker_exited===true && proof.controller_exited===true);
  if(c.backend==='linux_pid_namespace') requireThat(namespaceFinality(proof,attempt));
  requireThat(Array.isArray(proof.process_exits) && proof.process_exits.length<=128);
  const roleKey={watchdog:'controller',authority:'worker',keeper:'keeper'};
  const processExits=[];
  for(const p of attempt.processes) {
    if(p.exit_observed) continue;
    requireThat(p.pid!==null && c.spawn_ids.includes(p.spawn_id),'verification_cleanup_unconfirmed');
    const nativeIdentity=(c.descriptor.identities || c.descriptor)[roleKey[p.role]];
    requireThat(nativeIdentity && nativeIdentity.pid===p.pid,'verification_process_identity_mismatch');
    const exit=proof.process_exits.find(item=>item.pid===p.pid &&
      (nativeIdentity.os_creation_time!==undefined ? item.os_creation_time===nativeIdentity.os_creation_time : true) &&
      (nativeIdentity.start_ticks!==undefined ? item.start_ticks===nativeIdentity.start_ticks : true));
    requireThat(exit && ['process_handle_signaled','windows_birth_absent','linux_pidfd_exit','linux_boot_birth_absent','linux_boot_birth_replaced','linux_namespace_init_exit'].includes(exit.method),'verification_process_identity_mismatch');
    requireThat(exit.method!=='linux_namespace_init_exit' || c.backend==='linux_pid_namespace' && roleKey[p.role]==='worker' && proof.namespace_drained===true,'verification_process_identity_mismatch');
    // For a nonce-based registry observation the immutable native descriptor,
    // including its kernel birth, provides the cross-session identity binding.
    requireThat(p.os_creation_time===null || p.os_creation_time===exit.os_creation_time,'verification_process_identity_mismatch');
    processExits.push({spawn_id:p.spawn_id,pid:p.pid,os_creation_time:p.os_creation_time,
      ...(p.os_creation_time===null?{process_nonce:p.process_nonce}:{}),method:exit.method});
  }
  if(proof.container_proof_basis==='persisted_native_cleanup_receipt') requireThat(c.cleanup_receipt!==null &&
    proof.cleanup_receipt_sha256===hash(JSON.stringify(c.cleanup_receipt)),'verification_process_identity_mismatch');
  const result={...proof,attempt_id:attempt.attempt_id,generation:attempt.generation,
    descriptor_sha256:c.descriptor_sha256,process_exits:processExits,
    native_return:copyInertData(nativeProof)};
  delete result.evidence_sha256;
  result.evidence_sha256=hash(JSON.stringify(result));
  return result;
}
function createNativeRecovery(attempt, options={}) {
  const backend=backendFor(attempt);
  const darwin=attempt.containment.backend==='darwin_private_ruid';
  const remaining=()=>{
    const value=options.remainingMs ? Math.floor(options.remainingMs()) : attempt.profile.cleanup_budget_ms;
    requireThat(Number.isSafeInteger(value) && value>0,'verification_recovery_budget_exceeded');
    return Math.min(600000,value);
  };
  requireThat(typeof backend.currentProcessIdentity==='function' && typeof backend.verifyProcessExit==='function' &&
    typeof backend.recoverContainer==='function','verification_native_recovery_unavailable');
  const adapter=snapshot=>{
    requireThat(snapshot?.recovery?.status==='active' && snapshot.stop_reason!==null,'verification_recovery_fence_missing');
    requireThat(snapshot.attempt_id===attempt.attempt_id && snapshot.generation===attempt.generation &&
      snapshot.containment?.descriptor_sha256===attempt.containment.descriptor_sha256,'verification_attempt_mismatch');
    const native=backend.recoverContainer(copyInertData(snapshot.containment.descriptor),
      {cleanup_timeout_ms:darwin?remaining():snapshot.profile.cleanup_budget_ms,cleanup_receipt:copyInertData(snapshot.containment.cleanup_receipt)});
    if(darwin)remaining();
    if(native?.status!=='completed') fail(typeof native?.code==='string' && /^[a-z0-9_]{1,128}$/.test(native.code)?native.code:'verification_cleanup_unconfirmed');
    return bindProof(snapshot,native);
  };
  adapter.owner_identity=copyInertData(darwin?backend.currentProcessIdentity(attempt.containment.descriptor,
    {timeoutMs:Math.min(5000,remaining())}):backend.currentProcessIdentity());
  adapter.verify_recoverer_exit=identity=>{
    const observed=copyInertData(darwin?backend.verifyProcessExit(attempt.containment.descriptor,copyInertData(identity),
      {timeoutMs:Math.min(5000,remaining())}):backend.verifyProcessExit(copyInertData(identity)));
    if(observed.status!=='exited') return {status:observed.status==='active'?'active':'unconfirmed'};
    return {status:'exited',owner_identity_sha256:hash(JSON.stringify(identity)),evidence_sha256:hash(JSON.stringify(observed))};
  };
  return adapter;
}
function recoverAttempt(context,input) {
  // The narrow no-process/controller-only proof needs no OS backend. A live
  // recovery reservation must instead be examined by its exact native owner.
  const started=process.hrtime.bigint();
  input=copyInertData(input);
  let requestedDeadline=null;
  if(input?.deadline_ns!==undefined) {
    requireThat(typeof input.deadline_ns==='string' && /^\d{1,32}$/.test(input.deadline_ns),'verification_clock_invalid');
    requestedDeadline=BigInt(input.deadline_ns);
    requireThat(process.hrtime.bigint()<requestedDeadline,'verification_recovery_budget_exceeded');
  }
  const status=control.readStatus(context),attempt=status.attempt;
  if(input?.invocation_nonce_sha256!==undefined || input?.invocation_scope_sha256!==undefined || attempt?.invocation) {
    requireThat(attempt && attempt.invocation,'verification_attempt_mismatch');
    const profileDeadline=started+BigInt(attempt.profile.cleanup_budget_ms)*1000000n;
    const deadline=requestedDeadline!==null && requestedDeadline<profileDeadline ? requestedDeadline : profileDeadline;
    requireThat(process.hrtime.bigint()<deadline,'verification_recovery_budget_exceeded');
    return control.recoverInvocation(context,{...input,deadline_ns:String(deadline)});
  }
  if(input?.startup_nonce_sha256!==undefined) {
    requireThat(typeof input.startup_nonce_sha256==='string' && /^[a-f0-9]{64}$/.test(input.startup_nonce_sha256) &&
      attempt?.storage_protocol===control.STORAGE_PROTOCOL && attempt.startup_nonce_sha256===input.startup_nonce_sha256,
      'verification_attempt_mismatch');
    requireThat(input.attempt_id===undefined && input.generation===undefined ||
      input.attempt_id===attempt.attempt_id && input.generation===attempt.generation,'verification_attempt_mismatch');
    input={...input,attempt_id:attempt.attempt_id,generation:attempt.generation};
  }
  requireThat(attempt && input && attempt.attempt_id===input.attempt_id && attempt.generation===input.generation,'verification_attempt_mismatch');
  if(attempt.storage_protocol===control.STORAGE_PROTOCOL || requestedDeadline!==null) {
    const profileDeadline=started+BigInt(attempt.profile.cleanup_budget_ms)*1000000n;
    // A caller may shorten this invocation's admission epoch, never enlarge
    // the configured cleanup budget. Reading state and waiting for the old
    // storage writer both consume the same original monotonic epoch.
    const deadline=requestedDeadline!==null && requestedDeadline<profileDeadline ? requestedDeadline : profileDeadline;
    const remainingMs=()=>Math.floor(Number(deadline-process.hrtime.bigint())/1e6);
    const invoke=()=>{
      requireThat(remainingMs()>0,'verification_recovery_budget_exceeded');
      return recoverUnderLease(context,input,{remainingMs});
    };
    requireThat(remainingMs()>0,'verification_recovery_budget_exceeded');
    return attempt.storage_protocol===control.STORAGE_PROTOCOL ?
      control.withStorageLease(context,invoke,{timeoutMs:Math.min(600000,remainingMs())}) : invoke();
  }
  return recoverUnderLease(context,input);
}
function recoverUnderLease(context,input,options={}) {
  const attempt=control.readStatus(context).attempt;
  requireThat(attempt && attempt.attempt_id===input.attempt_id && attempt.generation===input.generation,'verification_attempt_mismatch');
  if(input.startup_nonce_sha256!==undefined)requireThat(attempt.startup_nonce_sha256===input.startup_nonce_sha256,'verification_attempt_mismatch');
  if(attempt.recovery?.status!=='active') {
    const narrow=control.recoverAttempt(context,input);
    if(narrow.status!=='requires_native_recovery') return narrow;
  }
  if(!attempt.containment) return {status:'requires_native_recovery',reason:'durable_native_descriptor_missing',attempt};
  try {return control.recoverAttempt(context,input,createNativeRecovery(attempt,options));}
  catch(error) {
    // Unsupported backend means no native action was attempted. Every action
    // failure after reservation is persisted by verification-control itself.
    if(['verification_native_recovery_unavailable','verification_recovery_descriptor_missing'].includes(error.code))
      return {status:'requires_native_recovery',reason:error.code,attempt:control.readStatus(context).attempt};
    throw error;
  }
}
// A fixed, newly contained recovery worker uses only the immutable selector.
// A missing or replaced invocation never grants authority over a successor.
function recoverOwnedInvocation(context,input) {
  input=copyInertData(input);
  requireThat(input && typeof input==='object' && !Array.isArray(input) &&
    Object.keys(input).every(key=>['invocation_nonce_sha256','invocation_scope_sha256','deadline_ns','recovery_reason'].includes(key)) &&
    /^[a-f0-9]{64}$/.test(input.invocation_nonce_sha256||'') && /^[a-f0-9]{64}$/.test(input.invocation_scope_sha256||'') &&
    typeof input.deadline_ns==='string' && /^\d{1,32}$/.test(input.deadline_ns) &&
    (input.recovery_reason===undefined || ['cancelled','work_timeout','progress_timeout','failure'].includes(input.recovery_reason)),
    'verification_control_invalid');
  const deadline=BigInt(input.deadline_ns);
  const check=()=>requireThat(process.hrtime.bigint()<deadline,'verification_recovery_budget_exceeded');
  const selected=a=>a?.invocation?.nonce_sha256===input.invocation_nonce_sha256 &&
    a.invocation.scope_sha256===input.invocation_scope_sha256;
  check();
  let attempt=control.readStatus(context).attempt;
  check();
  if(!attempt)return {status:'not_published',ack_released:false};
  if(!selected(attempt))return {status:'not_current',ack_released:false};
  try {
    const result=control.recoverInvocation(context,input);
    check();
    requireThat(result?.ack_released===false,'verification_cleanup_unconfirmed');
    return result;
  } catch(error) {
    if(error.code!=='verification_attempt_mismatch')throw error;
    // The native query may overlap another exact reclaimer and a successor.
    // Re-read under the same deadline; never replay the old proof on new state.
    check();attempt=control.readStatus(context).attempt;check();
    if(!attempt)return {status:'not_published',ack_released:false};
    if(!selected(attempt))return {status:'not_current',ack_released:false};
    throw error;
  }
}
module.exports={recoverAttempt,recoverOwnedInvocation,createNativeRecovery,bindProof};
