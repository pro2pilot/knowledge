'use strict';

// Fixed bridge from native Darwin observations to the common control ledger.
// Current normal teardown can authorize acceptance. A fresh read-only scope
// observation can authorize recovery only; it never becomes a current ACK.
const crypto = require('node:crypto');
const { copyInertData } = require('./inert-data');
const scopeProof = require('./verification-darwin-scope');
const wire = require('./verification-darwin-session-protocol');
const SCHEMA = 'knowledge-darwin-control-descriptor.v1';
const METHOD = 'darwin_private_ruid';
const STORAGE_PROTOCOL = 'lifetime_lease.v1';
const digest = value => crypto.createHash('sha256').update(JSON.stringify(value)).digest('hex');
const exact = (value, keys) => value && !Array.isArray(value) && typeof value === 'object' &&
  Object.keys(value).sort().join(',') === [...keys].sort().join(',');
const same = (a,b) => wire.canonical(a) === wire.canonical(b);
const fail = code => { throw Object.assign(new Error(code), { code }); };
const requireThat = (condition,code='verification_darwin_control_proof_invalid') => { if(!condition)fail(code); };
function inert(value, maximum=65536) {
  try { return copyInertData(value,null,maximum); }
  catch { fail('verification_darwin_control_proof_invalid'); }
}
function freeze(value) {
  if(value && typeof value==='object'){for(const child of Object.values(value))freeze(child);Object.freeze(value);}
  return value;
}
function validateDescriptor(value) {
  try {
    value=inert(value,32768);
    if(!exact(value,['schema_version','backend','storage_protocol','scope','controller_identity','authority_identity']) ||
      value.schema_version!==SCHEMA || value.backend!==METHOD || value.storage_protocol!==STORAGE_PROTOCOL ||
      !scopeProof.validateCommandScope(value.scope) || !scopeProof.validateProcessIdentity(value.controller_identity))return false;
    const native=value.scope.binding.descriptor;
    for(const id of [value.controller_identity,value.authority_identity]) {
      if(id===null)continue;
      if(!scopeProof.validateProcessIdentity(id) || id.host_id!==native.host_id || id.boot_id!==native.boot_id ||
        id.owner_uid!==native.owner_uid)return false;
    }
    return value.authority_identity===null ||
      value.authority_identity.birth.pid!==value.controller_identity.birth.pid &&
      value.authority_identity.birth.parent_unique_id===value.controller_identity.birth.unique_id;
  } catch { return false; }
}
function descriptor(input) {
  input=inert(input,32768);
  requireThat(exact(input,['scope','controller_identity','authority_identity']),'verification_darwin_control_descriptor_invalid');
  const value={schema_version:SCHEMA,backend:METHOD,storage_protocol:STORAGE_PROTOCOL,
    scope:input.scope,controller_identity:input.controller_identity,authority_identity:input.authority_identity};
  requireThat(validateDescriptor(value),'verification_darwin_control_descriptor_invalid');return freeze(value);
}
function validateAttemptBinding(attempt, containment=attempt?.containment) {
  try {
    if(attempt?.storage_protocol!==STORAGE_PROTOCOL || !validateDescriptor(containment?.descriptor) ||
      containment.backend!==METHOD || !Array.isArray(containment.spawn_ids) || !Array.isArray(attempt.processes))return false;
    const d=containment.descriptor,identity=d.authority_identity;
    if(attempt.startup_nonce_sha256!==wire.sha(d.scope.binding.descriptor.attempt_nonce))return false;
    if(identity===null)return containment.spawn_ids.length===0 && attempt.processes.length===0;
    if(attempt.processes.length!==1 || containment.spawn_ids.length!==1)return false;
    const process=attempt.processes[0];
    return process.role==='authority' && process.spawn_id===1 && containment.spawn_ids[0]===1 &&
      process.pid===identity.birth.pid && process.os_creation_time===null && process.process_nonce===attempt.generation &&
      Object.values(d.scope.binding.descriptor.allowed_runtimes).includes(process.executable_sha256);
  } catch { return false; }
}
function normalProof(input) {
  const {descriptor:d,terminalReply,capability,authorityExit}=inert(input);
  requireThat(validateDescriptor(d) && d.authority_identity!==null);
  const native=d.scope.binding.descriptor;
  requireThat(capability && ['source_sha256','stub_source_sha256','stub_binary_sha256','transport_header_sha256',
    'uid_history_header_sha256','uid_history_source_sha256','installation_id','account_policy_id','account_policy_sha256',
    'host_id','boot_id','daemon_epoch'].every(key=>capability[key]===native[key]) &&
    capability.binary_sha256===native.broker_binary_sha256);
  const proof=wire.validateProof(terminalReply,d.scope.binding,capability,true);
  requireThat(same(proof.authority_identity,d.authority_identity.birth) && same(proof.controller_identity,d.controller_identity.birth));
  requireThat(exact(authorityExit,['pid','process_nonce','method','exit_observed']) &&
    authorityExit.pid===d.authority_identity.birth.pid && /^[a-f0-9]{32}$/.test(authorityExit.process_nonce) &&
    authorityExit.method==='process_handle_signaled' && authorityExit.exit_observed===true);
  return {status:'completed',method:METHOD,descriptor_sha256:digest(d),
    native_descriptor_sha256:d.scope.binding.descriptor_sha256,native_terminal_sha256:terminalReply.proof_sha256,
    storage_protocol:STORAGE_PROTOCOL,controller_excluded_from_boundary:true,
    proof_kind:'normal_current',proof_current:true,cleanup_only:false,active_processes:0,
    worker_exited:true,guardian_exited:true,guardian_exit_confirmed:true,root_child_exit_confirmed:true,controller_exited:false,
    authority_identity:d.authority_identity,authority_exit:authorityExit,
    terminal_reply:terminalReply,capability};
}
function capabilityFromObservation(observation) {
  return Object.fromEntries(['source_sha256','stub_source_sha256','transport_header_sha256',
    'uid_history_header_sha256','uid_history_source_sha256','binary_sha256','stub_binary_sha256',
    'daemon_epoch','host_id','boot_id'].map(key=>[key,observation[key]]));
}
function recoveryProof(d, observation) {
  requireThat(validateDescriptor(d));observation=inert(observation);
  const checked=scopeProof.validateObservation(observation,d.scope,capabilityFromObservation(observation),observation.observation_nonce);
  requireThat(checked.status==='completed' && checked.cleanup_only===true && checked.proof_current===false);
  const native=d.scope.binding.descriptor;
  const resolved=observation.authority_identity===null?null:{schema:'knowledge-darwin-process-identity.v1',
    host_id:native.host_id,boot_id:native.boot_id,owner_uid:native.owner_uid,birth:observation.authority_identity};
  requireThat(resolved===null || scopeProof.validateProcessIdentity(resolved));
  requireThat(d.authority_identity===null || same(resolved,d.authority_identity));
  if(resolved)requireThat(resolved.birth.parent_unique_id===d.controller_identity.birth.unique_id);
  return {status:'completed',method:METHOD,descriptor_sha256:digest(d),
    native_descriptor_sha256:d.scope.binding.descriptor_sha256,native_terminal_sha256:null,
    storage_protocol:STORAGE_PROTOCOL,controller_excluded_from_boundary:true,
    proof_kind:'recovery_observation',proof_current:false,cleanup_only:true,active_processes:0,
    worker_exited:resolved!==null,guardian_exited:true,guardian_exit_confirmed:true,root_child_exit_confirmed:true,controller_exited:false,
    resolved_authority_identity:resolved,
    pre_registration_bootstrap_exit:d.authority_identity===null?'not_observed':'not_applicable',
    scope_observation:observation,observation_sha256:checked.observation_sha256};
}
function validateProof(proof, d, {allowRecovery=false}={}) {
  try {
    proof=inert(proof);
    let expected;
    if(proof?.proof_kind==='normal_current') expected=normalProof({descriptor:d,
      terminalReply:proof.terminal_reply,capability:proof.capability,authorityExit:proof.authority_exit});
    else if(allowRecovery && proof?.proof_kind==='recovery_observation')expected=recoveryProof(d,proof.scope_observation);
    else return false;
    return Object.entries(expected).every(([key,value])=>same(proof[key],value));
  } catch { return false; }
}
function configFor(d) {
  requireThat(validateDescriptor(d),'verification_darwin_control_descriptor_invalid');
  return {enabled:true,mode:'isolated_copy',broker_path:d.scope.broker_path,broker_socket:d.scope.broker_socket,copy:{}};
}
function currentProcessIdentity(d,{timeoutMs=5000}={}) {
  const observed=scopeProof.currentProcessIdentity(configFor(d),{timeoutMs});
  requireThat(observed.status==='observed' && scopeProof.validateProcessIdentity(observed.identity),
    'verification_recovery_owner_unconfirmed');
  return observed.identity;
}
function verifyProcessExit(d, identity, {timeoutMs=5000}={}) {
  return scopeProof.verifyProcessExit(configFor(d),identity,{timeoutMs});
}
function recoverContainer(d,{cleanup_timeout_ms=30000}={}) {
  requireThat(validateDescriptor(d),'verification_darwin_control_descriptor_invalid');
  const checked=scopeProof.recoverCommandScope(d.scope,{timeoutMs:Math.min(600000,cleanup_timeout_ms)});
  if(checked.status!=='completed')return {status:'unconfirmed',method:METHOD,code:checked.code||'verification_darwin_scope_unconfirmed'};
  return recoveryProof(d,checked.observation);
}
module.exports={SCHEMA,METHOD,STORAGE_PROTOCOL,descriptor,validateDescriptor,validateAttemptBinding,
  normalProof,validateProof,currentProcessIdentity,verifyProcessExit,recoverContainer};
