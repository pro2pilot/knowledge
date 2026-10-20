'use strict';

// Durable coarse state-root lease. The short contained lock serializes CAS;
// it is never the lease, and its stale recovery never clears an active attempt.
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const os = require('os');
const { copyInertData } = require('./inert-data');
const { assertSafeContainmentRoot, assertSafeContainedPath, ensureContainedDir,
  writeJsonAtomicContained } = require('./json-store');
const { withContainedLock } = require('./contained-lock-manager');
const { LOCKS } = require('./lock-policy');

const LEGACY_SCHEMA = 'knowledge-verification-control.v1';
const PREVIOUS_SCHEMA = 'knowledge-verification-control.v2';
const SCHEMA = 'knowledge-verification-control.v3';
const TRANSCRIPT_SCHEMA = 'knowledge-native-cleanup-transcript.v1';
const MAX_TRANSCRIPT_BYTES = 64 * 1024;
const LOCAL_RECOVERER_NONCE = crypto.randomBytes(32).toString('hex');
const MAX_BYTES = 256 * 1024;
const HASH = /^[a-f0-9]{64}$/;
const ID = /^VAT-[a-f0-9]{32}$/;
const GENERATION = /^[a-f0-9]{32}$/;
const PHASES = new Set(['reserved','preparing','running','finalizing','cleanup_pending','cleanup_unconfirmed','terminal']);
const ROLES = new Set(['watchdog','authority','supervisor','worker','keeper','command','descendant']);
const MILESTONES = new Set(['admission_complete','containment_ready','artifact_verified','command_verified','readback_complete','finalization_verified']);
const REASONS = new Set(['user_requested','shutdown','superseded','operator_recovery']);
const OUTCOMES = new Set(['passed','failed','cancelled','timed_out']);
const STAGES = new Set(['setup','test_setup','command','finalization','receipt_commit','between_tests','batch_receipt','cleanup']);
const WAIT_REASONS = new Set(['work','cleanup','cancel','work_timeout','progress_timeout']);
const resourceScopes = new Set();
const resourceKey = loc => loc.rootIdentity.dev + ':' + loc.rootIdentity.ino;
const hash = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
const now = () => new Date().toISOString();
function fail(code, message) { throw Object.assign(new Error(message || code), { code }); }
function requireThat(test, code = 'verification_control_invalid') { if (!test) fail(code); }
function integer(v, min = 0, max = Number.MAX_SAFE_INTEGER) { return Number.isSafeInteger(v) && v >= min && v <= max; }
function exact(value, keys) { return value && !Array.isArray(value) && typeof value === 'object' && Object.keys(value).sort().join(',') === [...keys].sort().join(','); }
function iso(value) { return typeof value === 'string' && value.length <= 64 && Number.isFinite(Date.parse(value)); }
function identity(stat) { return { dev: String(stat.dev), ino: String(stat.ino) }; }
function same(a,b) { return JSON.stringify(a) === JSON.stringify(b); }
function inert(value) { try { return copyInertData(value); } catch { fail('verification_control_invalid'); } }
function normalizeProfile(input = {}) {
  input = inert(input);
  requireThat(input && !Array.isArray(input) && typeof input === 'object');
  requireThat(Object.keys(input).every(k => ['work_budget_ms','no_progress_ms','cleanup_budget_ms'].includes(k)));
  requireThat(Object.values(input).every(v=>v!==null),'verification_profile_invalid');
  const profile = { work_budget_ms: input.work_budget_ms ?? 120000,
    no_progress_ms: input.no_progress_ms ?? 60000,
    cleanup_budget_ms: input.cleanup_budget_ms ?? 30000 };
  requireThat(integer(profile.work_budget_ms,1,600000*100000) && integer(profile.no_progress_ms,0,600000*100000) &&
    integer(profile.cleanup_budget_ms,1,3600000), 'verification_profile_invalid');
  return profile;
}
function location(context) {
  requireThat(context && typeof context.stateRoot === 'string' && path.isAbsolute(context.stateRoot));
  const root = assertSafeContainmentRoot(context.stateRoot);
  const rootIdentity = identity(fs.lstatSync(root,{bigint:true}));
  const directory = path.join(root,'maintenance','verification-control');
  return { root, rootIdentity, directory, active: path.join(directory,'active.json') };
}
function physicalRead(loc,file) {
  try {
    assertSafeContainedPath(loc.root,file);
    const before = fs.lstatSync(file,{bigint:true});
    requireThat(before.isFile() && !before.isSymbolicLink() && before.nlink === 1n && before.size <= BigInt(MAX_BYTES),'verification_control_unsafe');
    const fd = fs.openSync(file,fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0));
    try {
      const opened = fs.fstatSync(fd,{bigint:true});
      requireThat(opened.isFile() && opened.nlink === 1n && opened.size <= BigInt(MAX_BYTES),'verification_control_unsafe');
      requireThat(same(identity(before),identity(opened)),'verification_control_read_raced');
      const buffer=Buffer.alloc(MAX_BYTES+1);let size=0,count;
      do {count=fs.readSync(fd,buffer,size,buffer.length-size,null);size+=count;} while(count>0 && size<buffer.length);
      const bytes=buffer.subarray(0,size),after=fs.fstatSync(fd,{bigint:true}),live=fs.lstatSync(file,{bigint:true});
      requireThat(bytes.length <= MAX_BYTES && after.nlink<=1n && live.nlink===1n,'verification_control_unsafe');
      requireThat(after.nlink===1n,'verification_control_read_raced');
      requireThat(same(identity(opened),identity(after)) && same(identity(after),identity(live)) && opened.size === after.size && after.size === live.size,'verification_control_read_raced');
      return JSON.parse(bytes.toString('utf8'));
    } finally { fs.closeSync(fd); }
  } catch (e) {
    // ENOENT anywhere in an existing control path is not silently swallowed by
    // status if active.json itself was physically present but raced away.
    if (['verification_control_unsafe','verification_control_read_raced'].includes(e.code)) throw e;
    fail('verification_control_corrupt');
  }
}
function validate(a,loc) {
  // v1 remains readable. A successful mutation upgrades its envelope without
  // inventing native ownership for historical unnamed containers.
  if (a && a.schema_version === LEGACY_SCHEMA && exact(a,['schema_version','attempt_id','generation','revision','root_identity','request_sha256','owner_token_sha256','initiator','profile','phase','claimed','created_at','updated_at','cancel','stop_reason','runtime_observation','progress','progress_history','processes','cleanup','terminal'])) {
    a = {...a,schema_version:PREVIOUS_SCHEMA,containment:null,recovery:null};
  }
  if(a && a.schema_version===PREVIOUS_SCHEMA && exact(a.cleanup,['status','attempts','evidence_sha256']))
    a={...a,schema_version:SCHEMA,cleanup:{...a.cleanup,native_transcript:null,transcript_required:false}};
  requireThat(exact(a,['schema_version','attempt_id','generation','revision','root_identity','request_sha256','owner_token_sha256','initiator','profile','phase','claimed','created_at','updated_at','cancel','stop_reason','runtime_observation','progress','progress_history','processes','cleanup','terminal','containment','recovery']),'verification_control_corrupt');
  requireThat(a.schema_version === SCHEMA && ID.test(a.attempt_id) && GENERATION.test(a.generation) && integer(a.revision,1) &&
    same(a.root_identity,loc.rootIdentity) && HASH.test(a.request_sha256) && HASH.test(a.owner_token_sha256) &&
    same(normalizeProfile(a.profile),a.profile) && PHASES.has(a.phase) && typeof a.claimed === 'boolean' && iso(a.created_at) && iso(a.updated_at),'verification_control_corrupt');
  requireThat(exact(a.initiator,['pid','agent_id','host_sha256','process_creation_time']) && integer(a.initiator.pid,1) &&
    (a.initiator.agent_id===null || /^[A-Za-z0-9_.-]{1,128}$/.test(a.initiator.agent_id)) && HASH.test(a.initiator.host_sha256) && a.initiator.process_creation_time===null,'verification_control_corrupt');
  requireThat(exact(a.cancel,['requested','reason_code','at']) && typeof a.cancel.requested === 'boolean' &&
    (a.cancel.requested ? REASONS.has(a.cancel.reason_code) && iso(a.cancel.at) : a.cancel.reason_code === null && a.cancel.at === null),'verification_control_corrupt');
  requireThat([null,'work_timeout','progress_timeout','failure'].includes(a.stop_reason),'verification_control_corrupt');
  if(a.runtime_observation!==null) {
    const o=a.runtime_observation;
    requireThat(exact(o,['stage','elapsed_ms','last_meaningful_progress_elapsed_ms','progress_signal_available','wait_reason','observed_at']) && STAGES.has(o.stage) && WAIT_REASONS.has(o.wait_reason) &&
      Number.isFinite(o.elapsed_ms) && o.elapsed_ms>=0 && o.elapsed_ms<=Number.MAX_SAFE_INTEGER && Number.isFinite(o.last_meaningful_progress_elapsed_ms) && o.last_meaningful_progress_elapsed_ms>=0 && o.last_meaningful_progress_elapsed_ms<=o.elapsed_ms && typeof o.progress_signal_available==='boolean' && iso(o.observed_at),'verification_control_corrupt');
  }
  requireThat(exact(a.progress,['sequence','milestone','ordinal','evidence_sha256','at']) && integer(a.progress.sequence) && integer(a.progress.ordinal) &&
    (a.progress.sequence === 0 ? a.progress.milestone === null && a.progress.evidence_sha256 === null && a.progress.at === null : MILESTONES.has(a.progress.milestone) && HASH.test(a.progress.evidence_sha256) && iso(a.progress.at)),'verification_control_corrupt');
  requireThat(Array.isArray(a.progress_history) && a.progress_history.length===a.progress.sequence && a.progress_history.length<=1024,'verification_control_corrupt');
  const seenProgress=new Set();let lastOrdinal=0;
  for(const p of a.progress_history){requireThat(exact(p,['milestone','ordinal','evidence_sha256']) && MILESTONES.has(p.milestone) && integer(p.ordinal,1) && p.ordinal>lastOrdinal && HASH.test(p.evidence_sha256) && !seenProgress.has(p.milestone+':'+p.evidence_sha256),'verification_control_corrupt');lastOrdinal=p.ordinal;seenProgress.add(p.milestone+':'+p.evidence_sha256);}
  requireThat(lastOrdinal===a.progress.ordinal,'verification_control_corrupt');
  requireThat(Array.isArray(a.processes) && a.processes.length <= 128,'verification_control_corrupt');
  for(let i=0;i<a.processes.length;i++) {
    const p=a.processes[i];
    requireThat(exact(p,['spawn_id','role','pid','os_creation_time','process_nonce','executable_sha256','exit_observed']) && p.spawn_id === i+1 && ROLES.has(p.role) && typeof p.exit_observed === 'boolean','verification_control_corrupt');
    requireThat(p.pid === null ? p.os_creation_time === null && p.process_nonce === null && p.executable_sha256 === null && !p.exit_observed : integer(p.pid,1) &&
      (iso(p.os_creation_time) && p.process_nonce === null || p.os_creation_time === null && /^[a-f0-9]{32,64}$/.test(p.process_nonce)) && HASH.test(p.executable_sha256),'verification_control_corrupt');
  }
  requireThat(exact(a.cleanup,['status','attempts','evidence_sha256','native_transcript','transcript_required']) && ['not_started','pending','unconfirmed','confirmed'].includes(a.cleanup.status) && integer(a.cleanup.attempts) &&
    typeof a.cleanup.transcript_required==='boolean' &&
    (a.cleanup.evidence_sha256 === null || HASH.test(a.cleanup.evidence_sha256)),'verification_control_corrupt');
  if(a.containment!==null) {
    const c=a.containment;
    if(exact(c,['backend','descriptor_sha256','descriptor','spawn_ids'])) c.cleanup_receipt=null;
    requireThat(exact(c,['backend','descriptor_sha256','descriptor','spawn_ids','cleanup_receipt']) &&
      ['windows_job_object','linux_pid_namespace'].includes(c.backend) &&
      c.descriptor && !Array.isArray(c.descriptor) && typeof c.descriptor==='object' && c.descriptor.backend===c.backend &&
      HASH.test(c.descriptor_sha256) && hash(JSON.stringify(c.descriptor))===c.descriptor_sha256 &&
      Buffer.byteLength(JSON.stringify(c.descriptor))<=32768 && Array.isArray(c.spawn_ids) && c.spawn_ids.length>0 &&
      c.spawn_ids.every((id,i)=>integer(id,1,a.processes.length) && (i===0 || c.spawn_ids[i-1]<id)),'verification_control_corrupt');
    if(c.cleanup_receipt!==null) {
      const receipt=c.cleanup_receipt,{evidence_sha256,...observed}=receipt;
      requireThat(validNativeContainerProof({...a,recovery:null},receipt) && evidence_sha256===hash(JSON.stringify(observed)) &&
        Buffer.byteLength(JSON.stringify(receipt))<=16384,'verification_control_corrupt');
    }
  }
  if(a.recovery!==null) {
    const r=a.recovery;
    requireThat(exact(r,['ordinal','recovery_id','token_sha256','owner_identity','started_at','status','reason_code']) &&
      integer(r.ordinal,1) && GENERATION.test(r.recovery_id) && HASH.test(r.token_sha256) &&
      r.owner_identity && !Array.isArray(r.owner_identity) && typeof r.owner_identity==='object' &&
      Buffer.byteLength(JSON.stringify(r.owner_identity))<=8192 && iso(r.started_at) &&
      ['active','unconfirmed','completed'].includes(r.status) &&
      (r.reason_code===null || typeof r.reason_code==='string' && /^[a-z0-9_]{1,128}$/.test(r.reason_code)) &&
      a.stop_reason!==null,'verification_control_corrupt');
  }
  if(a.cleanup.native_transcript!==null) validateTranscript(a,a.cleanup.native_transcript);
  if(a.phase === 'terminal') {
    requireThat(!a.cleanup.transcript_required || a.containment===null || a.cleanup.native_transcript!==null,'verification_control_corrupt');
    requireThat(!a.claimed && a.cleanup.status === 'confirmed' && exact(a.terminal,['outcome','ack_sha256']) && OUTCOMES.has(a.terminal.outcome),'verification_control_corrupt');
    requireThat(a.terminal.outcome === 'passed' ? !a.cancel.requested && a.stop_reason===null && HASH.test(a.terminal.ack_sha256) : a.terminal.ack_sha256 === null,'verification_control_corrupt');
    requireThat(a.processes.every(p=>p.pid!==null && p.exit_observed),'verification_control_corrupt');
  } else requireThat(a.claimed && a.terminal === null && a.cleanup.status !== 'confirmed','verification_control_corrupt');
  return a;
}
function load(loc) {
  // Missing whole tree is the initial state. Existing unsafe/non-file targets
  // and malformed state fail closed rather than becoming an empty registry.
  try { fs.lstatSync(loc.active); }
  catch(e) { if(e.code === 'ENOENT') { assertSafeContainedPath(loc.root,loc.active,{allowMissing:true});if(fs.existsSync(loc.directory))fail('verification_control_missing');return null; } throw e; }
  for(let n=0;n<3;n++){try{return validate(physicalRead(loc,loc.active),loc);}catch(e){if(e.code!=='verification_control_read_raced'||n===2)throw e;}}
}
function write(loc,a) {
  validate(a,loc);
  requireThat(Buffer.byteLength(JSON.stringify(a)) <= MAX_BYTES,'verification_control_oversized');
  ensureContainedDir(loc.root,loc.directory);
  writeJsonAtomicContained(loc.active,a,loc.root);
  requireThat(same(load(loc),a),'verification_control_readback_failed');
}
function mutate(context, fn) {
  const loc=location(context);
  requireThat(!resourceScopes.has(resourceKey(loc)),'verification_resource_busy');
  return withContainedLock({context,rootKind:'state',rootPath:loc.root,lockName:'verification-control',purpose:LOCKS['verification-control'].purpose,timeoutMs:5000},()=>fn(loc,load(loc)));
}
function publicAttempt(a) {
  if(!a) return null;
  const {owner_token_sha256,root_identity,...view}=a;
  return inert(view);
}
function ownerCheck(a,owner) {
  owner=inert(owner);
  requireThat(a && owner && owner.attempt_id===a.attempt_id && owner.generation===a.generation && typeof owner.token==='string' && /^[a-f0-9]{64}$/.test(owner.token),'verification_owner_invalid');
  const actual=Buffer.from(hash(owner.token)), expected=Buffer.from(a.owner_token_sha256);
  requireThat(crypto.timingSafeEqual(actual,expected),'verification_owner_invalid');
}
function changed(loc,a) { a.revision++;a.updated_at=now();write(loc,a);return publicAttempt(a); }
function beginAttempt(context, options) {
  options=inert(options); requireThat(options && HASH.test(options.request_sha256));
  const profile=normalizeProfile(options.profile);
  return mutate(context,(loc,a)=>{
    if(a?.claimed) fail('verification_recovery_required','An active verification owns this state root; inspect status/cancel/recover.');
    if(a) {
      const archived=path.join(loc.directory,'attempts',a.attempt_id+'.json');
      ensureContainedDir(loc.root,path.dirname(archived));
      if(fs.existsSync(archived)) requireThat(same(validate(physicalRead(loc,archived),loc),a),'verification_control_corrupt');
      else writeJsonAtomicContained(archived,a,loc.root);
    }
    const token=crypto.randomBytes(32).toString('hex'),at=now();
    a={schema_version:SCHEMA,attempt_id:'VAT-'+crypto.randomBytes(16).toString('hex'),generation:crypto.randomBytes(16).toString('hex'),revision:1,root_identity:loc.rootIdentity,
      request_sha256:options.request_sha256,owner_token_sha256:hash(token),initiator:{pid:process.pid,agent_id:/^[A-Za-z0-9_.-]{1,128}$/.test(process.env.KNOWLEDGE_AGENT_ID||'')?process.env.KNOWLEDGE_AGENT_ID:null,host_sha256:hash(os.hostname()),process_creation_time:null},profile,phase:'reserved',claimed:true,created_at:at,updated_at:at,
      cancel:{requested:false,reason_code:null,at:null},stop_reason:null,runtime_observation:null,progress:{sequence:0,milestone:null,ordinal:0,evidence_sha256:null,at:null},progress_history:[],processes:[],cleanup:{status:'not_started',attempts:0,evidence_sha256:null,native_transcript:null,transcript_required:true},terminal:null,containment:null,recovery:null};
    write(loc,a);
    return {attempt:publicAttempt(a),owner:{attempt_id:a.attempt_id,generation:a.generation,token}};
  });
}
function readStatus(context) {
  const a=load(location(context));
  const at=Date.now(),elapsed=a?Math.max(0,at-Date.parse(a.created_at)):null;
  const observed=a?.runtime_observation,snapshotAt=observed?.observed_at??a?.updated_at;
  const snapshotStaleness=a?Math.max(0,at-Date.parse(snapshotAt)):null;
  const progressAge=!a || observed?.progress_signal_available===false?null:observed
    ? Math.max(0,observed.elapsed_ms-observed.last_meaningful_progress_elapsed_ms)+snapshotStaleness
    : Math.max(0,at-Date.parse(a.progress.at??a.created_at));
  return {schema_version:SCHEMA,status:!a?'idle':a.claimed?'blocked':'terminal',operational_readiness:!a||!a.claimed?'not_blocked':'blocked',attempt:publicAttempt(a),observation:'persisted_snapshot_not_live_liveness',
    current_stage:!a?null:a.cleanup.status!=='not_started'?'cleanup':a.runtime_observation?.stage??'setup',
    waiting_reason:!a||!a.claimed?'none':a.cancel.requested?'cancel':a.stop_reason&&a.stop_reason!=='failure'?a.stop_reason:a.cleanup.status!=='not_started'?'cleanup':'work',
    timing:!a?null:{elapsed_ms:elapsed,elapsed_source:'wall_clock_estimate',observed_elapsed_ms:a.runtime_observation?.elapsed_ms??null,
      observed_last_meaningful_progress_elapsed_ms:a.runtime_observation?.last_meaningful_progress_elapsed_ms??null,
      since_meaningful_progress_ms:progressAge,
      progress_age_source:observed?'persisted_observation_plus_wall_clock_snapshot_staleness_estimate':'wall_clock_ledger_estimate',
      snapshot_staleness_ms:snapshotStaleness,snapshot_staleness_source:'wall_clock_estimate',
      progress_signal_available:a.runtime_observation?.progress_signal_available??null,snapshot_at:a.runtime_observation?.observed_at??a.updated_at}};
}
// Hold the same mutex used by claim issuance through a synchronous state-root
// mutation. Reentry is local to this call stack; other processes still acquire
// the physical mutex. No active verification owner is exempt from quarantine.
function withResourceAvailable(context,action) {
  requireThat(typeof action==='function','verification_control_invalid');
  const loc=location(context),key=resourceKey(loc);
  const invoke=()=>{const result=action();requireThat(!result || typeof result.then!=='function','verification_resource_async_unsupported');return result;};
  if(resourceScopes.has(key))return invoke();
  return mutate(context,(_loc,a)=>{
    if(a?.claimed)fail('verification_recovery_required');
    resourceScopes.add(key);
    try{return invoke();}finally{resourceScopes.delete(key);}
  });
}
function assertResourceAvailable(context,owner=null) {
  return mutate(context,(_loc,a)=>{
    if(a?.claimed) { if(!owner) fail('verification_recovery_required');ownerCheck(a,owner);if(a.cancel.requested)fail('verification_cancelled');if(a.stop_reason)fail('verification_stopped'); }
    return {status:'available'};
  });
}
function updateAttempt(context,owner,event) {
  event=inert(event);requireThat(event && typeof event.type==='string');
  return mutate(context,(loc,a)=>{
    ownerCheck(a,owner);requireThat(a.claimed,'verification_already_terminal');
    if(event.expected_revision!==undefined)requireThat(event.expected_revision===a.revision,'verification_control_conflict');
    // The original authority may append exact exit observations and monotonic
    // native cleanup evidence. Neither fact changes the work fence, reservation,
    // cleanup phase, or the prohibition on a late ACK.
    if(a.recovery!==null && !['process_exit','cleanup_proven'].includes(event.type)) fail('verification_recovery_in_progress');
    if(event.type==='phase') {
      requireThat(!a.cancel.requested && !a.stop_reason && a.cleanup.status==='not_started','verification_stopped');
      const order=['reserved','preparing','running','finalizing'];
      requireThat(order.indexOf(event.phase)>order.indexOf(a.phase) && order.includes(event.phase),'verification_phase_invalid');a.phase=event.phase;
    } else if(event.type==='progress') {
      requireThat(!a.cancel.requested && !a.stop_reason && a.cleanup.status==='not_started','verification_stopped');
      requireThat(MILESTONES.has(event.milestone) && integer(event.ordinal,1) && event.ordinal>a.progress.ordinal && HASH.test(event.evidence_sha256),'verification_progress_invalid');
      requireThat(a.progress_history.length<1024 && !a.progress_history.some(p=>p.milestone===event.milestone && (p.evidence_sha256===event.evidence_sha256 || !['artifact_verified','command_verified'].includes(event.milestone))),'verification_progress_invalid');
      a.progress_history.push({milestone:event.milestone,ordinal:event.ordinal,evidence_sha256:event.evidence_sha256});
      a.progress={sequence:a.progress.sequence+1,milestone:event.milestone,ordinal:event.ordinal,evidence_sha256:event.evidence_sha256,at:now()};
    } else if(event.type==='containment_bound') {
      requireThat(!a.cancel.requested && !a.stop_reason && a.cleanup.status==='not_started' && a.containment===null,'verification_stopped');
      const descriptor=inert(event.descriptor),ids=inert(event.spawn_ids);
      requireThat(descriptor && !Array.isArray(descriptor) && typeof descriptor==='object' &&
        ['windows_job_object','linux_pid_namespace'].includes(descriptor.backend) && Buffer.byteLength(JSON.stringify(descriptor))<=32768 &&
        Array.isArray(ids) && ids.length>0 && ids.every((id,i)=>integer(id,1,a.processes.length) && (i===0 || ids[i-1]<id)),'verification_containment_invalid');
      a.containment={backend:descriptor.backend,descriptor_sha256:hash(JSON.stringify(descriptor)),descriptor,spawn_ids:ids,cleanup_receipt:null};
    } else if(event.type==='spawn_intent') {
      requireThat(!a.cancel.requested && !a.stop_reason && a.cleanup.status==='not_started','verification_stopped');
      requireThat(ROLES.has(event.role) && a.processes.length<128,'verification_spawn_invalid');
      a.processes.push({spawn_id:a.processes.length+1,role:event.role,pid:null,os_creation_time:null,process_nonce:null,executable_sha256:null,exit_observed:false});
    } else if(event.type==='spawn_aborted') {
      // The owning facade may retract only its last, still unissued syscall.
      // Cross-session recovery never infers this from a missing PID.
      const last=a.processes[a.processes.length-1];
      requireThat(event.reason==='before_spawn_syscall' && last?.spawn_id===event.spawn_id &&
        last.role==='watchdog' && last.pid===null,'verification_spawn_invalid');
      a.processes.pop();
    } else if(event.type==='spawn_observed' || event.type==='process_exit') {
      const p=a.processes.find(p=>p.spawn_id===event.spawn_id);requireThat(p,'verification_spawn_invalid');
      if(event.type==='spawn_observed') {
        const birth=event.os_creation_time??null,nonce=birth===null?(event.process_nonce??event.logical_nonce):null;
        requireThat(p.pid===null && integer(event.pid,1) && (iso(birth) || birth===null && /^[a-f0-9]{32,64}$/.test(nonce)) && HASH.test(event.executable_sha256),'verification_spawn_invalid');
        requireThat(!a.processes.some(other=>other.pid===event.pid && other.os_creation_time===birth && other.process_nonce===nonce),'verification_spawn_invalid');
        Object.assign(p,{pid:event.pid,os_creation_time:birth,process_nonce:nonce,executable_sha256:event.executable_sha256});
      } else {
        requireThat(p.pid!==null && p.pid===event.pid && p.os_creation_time===(event.os_creation_time??null) &&
          (p.os_creation_time!==null || p.process_nonce===(event.process_nonce??event.logical_nonce)) && event.method==='process_handle_signaled','verification_process_identity_mismatch');
        p.exit_observed=true;
      }
    } else if(event.type==='stop') {
      requireThat(['work_timeout','progress_timeout','failure'].includes(event.reason),'verification_stop_invalid');
      if(a.stop_reason)return {attempt:publicAttempt(a)};
      a.stop_reason=event.reason;
    } else if(event.type==='observation') {
      const previous=a.runtime_observation;
      requireThat(STAGES.has(event.stage) && WAIT_REASONS.has(event.wait_reason) && Number.isFinite(event.elapsed_ms) && event.elapsed_ms>=0 && event.elapsed_ms<=Number.MAX_SAFE_INTEGER &&
        Number.isFinite(event.last_meaningful_progress_elapsed_ms) && event.last_meaningful_progress_elapsed_ms>=0 && event.last_meaningful_progress_elapsed_ms<=event.elapsed_ms && typeof event.progress_signal_available==='boolean','verification_observation_invalid');
      requireThat(!previous || event.elapsed_ms>=previous.elapsed_ms && event.last_meaningful_progress_elapsed_ms>=previous.last_meaningful_progress_elapsed_ms,'verification_observation_stale');
      a.runtime_observation={stage:event.stage,elapsed_ms:event.elapsed_ms,last_meaningful_progress_elapsed_ms:event.last_meaningful_progress_elapsed_ms,progress_signal_available:event.progress_signal_available,wait_reason:event.wait_reason,observed_at:now()};
    } else if(event.type==='cleanup_proven') {
      requireThat(a.containment!==null && ['pending','unconfirmed'].includes(a.cleanup.status) && a.processes.every(p=>p.pid!==null && (p.role==='watchdog' || p.exit_observed)),'verification_cleanup_unconfirmed');
      const proof=bindCleanupProof(a,event.proof);
      // An owner receipt is an actual normal teardown observation. Starting
      // recovery must not grant this writer the recovery-only inference union.
      requireThat(validNativeContainerProof({...a,recovery:null},proof) && Buffer.byteLength(JSON.stringify(proof))<=16384,'verification_cleanup_unconfirmed');
      requireThat(a.containment.cleanup_receipt===null || same(a.containment.cleanup_receipt,proof),'verification_control_conflict');
      a.containment.cleanup_receipt=proof;
    } else if(event.type==='cleanup_started') {
      if(a.cleanup.status==='pending') return {attempt:publicAttempt(a)};
      a.cleanup.status='pending';a.cleanup.attempts++;a.phase='cleanup_pending';
    } else if(event.type==='cleanup_unconfirmed') {
      requireThat(a.cleanup.status==='pending' || a.cleanup.status==='unconfirmed','verification_cleanup_invalid');
      a.cleanup.status='unconfirmed';a.phase='cleanup_unconfirmed';
    } else fail('verification_control_event_invalid');
    return {attempt:changed(loc,a),...(event.type==='spawn_intent'?{spawn_id:a.processes.length}:{})};
  });
}
function requestCancel(context,input) {
  input=inert(input);requireThat(input && ID.test(input.attempt_id) && GENERATION.test(input.generation) && REASONS.has(input.reason_code ?? 'user_requested'));
  return mutate(context,(loc,a)=>{
    requireThat(a && a.attempt_id===input.attempt_id && a.generation===input.generation,'verification_attempt_mismatch');
    if(!a.claimed)return {status:'already_terminal',attempt:publicAttempt(a)};
    if(!a.cancel.requested){a.cancel={requested:true,reason_code:input.reason_code??'user_requested',at:now()};changed(loc,a);}
    return {status:'cancel_requested',attempt:publicAttempt(a)};
  });
}
function controllerOnly(a) {
  return a.containment===null && a.processes.length===1 && a.processes[0].role==='watchdog' && a.processes[0].pid!==null && a.processes[0].exit_observed===true;
}
function namespaceFinality(proof,allowInference) {
  if(proof.namespace_drained!==true || typeof proof.init_reaped!=='boolean') return false;
  if(proof.init_exit_observed===true && proof.init_exit_inferred!==true) {
    return proof.init_reaped===true || allowInference && proof.init_exit_basis==='linux_pidfd_exit' && proof.init_reap_basis==='kernel_namespace_init_final_exit';
  }
  return allowInference && proof.init_exit_observed===false && proof.init_exit_inferred===true && proof.init_reaped===false && proof.init_release_inferred===true &&
    ['linux_boot_birth_absent','linux_boot_birth_replaced'].includes(proof.init_exit_basis) && proof.init_reap_basis==='kernel_namespace_init_final_exit';
}
function validNativeContainerProof(a,proof) {
  return proof && proof.attempt_id===a.attempt_id && proof.generation===a.generation &&
    proof.status==='completed' && ['windows_job_object','linux_pid_namespace'].includes(proof.method) && proof.active_processes===0 &&
    (a.containment===null ? proof.method==='windows_job_object' : proof.method===a.containment.backend && proof.descriptor_sha256===a.containment.descriptor_sha256 && proof.worker_exited===true) &&
    proof.keeper_exited===true && (proof.method!=='linux_pid_namespace' || proof.worker_exited===true && namespaceFinality(proof,a.recovery!==null)) && HASH.test(proof.evidence_sha256);
}
function confirmedCleanup(a,proof) {
  proof=inert(proof);
  if(!proof || proof.attempt_id!==a.attempt_id || proof.generation!==a.generation)return false;
  if(proof.method==='no_processes_started')return a.processes.length===0;
  if(proof.method==='controller_only')return proof.status==='completed' && HASH.test(proof.evidence_sha256) && controllerOnly(a);
  return validNativeContainerProof(a,proof) && a.processes.length>0 && a.processes.every(p=>p.pid!==null && p.exit_observed);
}

// Preserve the exact native return before adding control-plane bindings. The
// digest covers both; callers must not hash a different, unbound projection.
function bindCleanupProof(owner,nativeProof) {
  const observed=inert(nativeProof);
  requireThat(observed && typeof observed==='object' && !Array.isArray(observed),'verification_cleanup_unconfirmed');
  const proof={...observed,attempt_id:owner.attempt_id,generation:owner.generation,native_return:observed};
  delete proof.evidence_sha256;
  proof.evidence_sha256=hash(JSON.stringify(proof));
  return proof;
}

function validateTranscript(a,t) {
  requireThat(exact(t,['schema_version','attempt_id','generation','descriptor_sha256','backend','recovery_id','recorded_at','payload_sha256','payload']) &&
    t.schema_version===TRANSCRIPT_SCHEMA && t.attempt_id===a.attempt_id && t.generation===a.generation &&
    a.containment!==null && t.descriptor_sha256===a.containment.descriptor_sha256 && t.backend===a.containment.backend &&
    t.recovery_id===(a.recovery?.recovery_id??null) && iso(t.recorded_at) && HASH.test(t.payload_sha256) &&
    exact(t.payload,['native_return','bound_proof']) && hash(JSON.stringify(t.payload))===t.payload_sha256 &&
    Buffer.byteLength(JSON.stringify(t))<=MAX_TRANSCRIPT_BYTES,'verification_control_corrupt');
  requireThat(validNativeContainerProof(a,t.payload.bound_proof) &&
    t.payload.bound_proof.evidence_sha256===a.cleanup.evidence_sha256 &&
    t.payload.native_return && typeof t.payload.native_return==='object' && !Array.isArray(t.payload.native_return),
    'verification_control_corrupt');
  requireThat(!a.cleanup.transcript_required || t.payload.bound_proof.native_return!==undefined,'verification_control_corrupt');
  requireThat(same(t.payload.native_return,t.payload.bound_proof.native_return??t.payload.bound_proof),'verification_control_corrupt');
  if(t.payload.bound_proof.native_return!==undefined) {
    const {evidence_sha256,...bound}=t.payload.bound_proof;
    requireThat(hash(JSON.stringify(bound))===evidence_sha256,'verification_control_corrupt');
  }
  // These records contain process observations, never an owner capability or
  // private signing material. Reject forbidden fields instead of redacting a
  // proof and making its saved digest impossible to reproduce.
  const visit=(value,depth=0)=>{
    requireThat(depth<=32,'verification_control_corrupt');
    if(value && typeof value==='object') for(const [key,item] of Object.entries(value)) {
      const normalized=key.replace(/[^a-z0-9]/gi,'').toLowerCase();
      requireThat(!['token','ownertoken','privatekey','privatekeypem','signingprivatekey'].includes(normalized),'verification_native_transcript_sensitive');
      visit(item,depth+1);
    }
  };
  visit(t.payload);
}
function transcript(a,proof) {
  const payload={native_return:inert(proof.native_return??proof),bound_proof:inert(proof)};
  return {schema_version:TRANSCRIPT_SCHEMA,attempt_id:a.attempt_id,generation:a.generation,
    descriptor_sha256:a.containment.descriptor_sha256,backend:a.containment.backend,
    recovery_id:a.recovery?.recovery_id??null,recorded_at:now(),payload_sha256:hash(JSON.stringify(payload)),payload};
}

function finishRecord(loc,a,input) {
  requireThat(input && OUTCOMES.has(input.outcome));
  requireThat(confirmedCleanup(a,input.cleanup_proof),'verification_cleanup_unconfirmed');
  requireThat(input.cleanup_proof.method!=='controller_only' || input.outcome!=='passed','verification_ack_invalid');
  requireThat(input.outcome!=='passed' || input.cleanup_proof.method!=='linux_pid_namespace' || input.cleanup_proof.init_reaped===true && input.cleanup_proof.init_exit_observed===true && input.cleanup_proof.init_exit_inferred!==true,'verification_cleanup_unconfirmed');
  if (input.deadline_ns !== undefined) {
    requireThat(typeof input.deadline_ns === 'string' && /^\d{1,32}$/.test(input.deadline_ns),'verification_control_invalid');
    if (process.hrtime.bigint() >= BigInt(input.deadline_ns)) a.stop_reason ||= 'failure';
  }
  const outcome=a.cancel.requested?'cancelled':['work_timeout','progress_timeout'].includes(a.stop_reason)?'timed_out':a.stop_reason==='failure'?'failed':input.outcome;
  requireThat(outcome!=='passed' || HASH.test(input.ack_sha256),'verification_ack_invalid');
  requireThat(input.ack_sha256===undefined || input.outcome==='passed','verification_ack_invalid');
  a.phase='terminal';a.claimed=false;a.cleanup.status='confirmed';
  if(a.recovery!==null) a.recovery.status='completed';
  a.cleanup.evidence_sha256=input.cleanup_proof.evidence_sha256??null;
  if(a.containment!==null) a.cleanup.native_transcript=transcript(a,input.cleanup_proof);
  a.terminal={outcome,ack_sha256:outcome==='passed'?input.ack_sha256:null};
  changed(loc,a);
  return {status:outcome,ack_released:outcome==='passed',attempt:publicAttempt(a)};
}
function commitFinish(context,owner,input) {
  input=inert(input);
  return mutate(context,(loc,a)=>{
    ownerCheck(a,owner);
    if(!a.claimed)return {status:a.terminal.outcome,ack_released:a.terminal.outcome==='passed',attempt:publicAttempt(a)};
    requireThat(a.recovery===null,'verification_recovery_in_progress');
    return finishRecord(loc,a,input);
  });
}
function recoverAttempt(context,input,nativeRecovery=null) {
  input=inert(input);const snapshot=load(location(context));
  requireThat(snapshot && input && snapshot.attempt_id===input.attempt_id && snapshot.generation===input.generation,'verification_attempt_mismatch');
  if(!snapshot.claimed)return {status:'already_terminal',attempt:publicAttempt(snapshot)};
  // Only existing exact-handle exit evidence can recover this narrow case.
  // Any authority/keeper/unknown spawn intent still needs a native adapter.
  if(typeof nativeRecovery!=='function') {
    requireThat(snapshot.recovery?.status!=='active','verification_recovery_in_progress');
    if(snapshot.processes.length===0) {
      return mutate(context,(loc,a)=>{
        requireThat(a && a.attempt_id===snapshot.attempt_id && a.generation===snapshot.generation && a.revision===snapshot.revision,'verification_control_conflict');
        return finishRecord(loc,a,{outcome:a.cancel.requested?'cancelled':'failed',
          cleanup_proof:{attempt_id:a.attempt_id,generation:a.generation,method:'no_processes_started'}});
      });
    }
    if(!controllerOnly(snapshot))return {status:'requires_native_recovery',attempt:publicAttempt(snapshot)};
    return mutate(context,(loc,a)=>{
      requireThat(a && a.attempt_id===snapshot.attempt_id && a.generation===snapshot.generation && a.revision===snapshot.revision,'verification_control_conflict');
      const proof={attempt_id:a.attempt_id,generation:a.generation,status:'completed',method:'controller_only',evidence_sha256:hash(JSON.stringify({attempt_id:a.attempt_id,generation:a.generation,processes:a.processes}))};
      return finishRecord(loc,a,{outcome:a.cancel.requested?'cancelled':'failed',cleanup_proof:proof});
    });
  }
  // Native actions are allowed only after a durable, irreversible work fence.
  // This reservation is independent of the short filesystem mutex. Its age is
  // never evidence of death and never releases the resource claim.
  let previousOwnerExit=null;
  if(snapshot.recovery?.status==='active') {
    requireThat(typeof nativeRecovery.verify_recoverer_exit==='function','verification_recovery_in_progress');
    previousOwnerExit=inert(nativeRecovery.verify_recoverer_exit(inert(snapshot.recovery.owner_identity)));
    requireThat(previousOwnerExit && previousOwnerExit.status==='exited' &&
      previousOwnerExit.owner_identity_sha256===hash(JSON.stringify(snapshot.recovery.owner_identity)) &&
      HASH.test(previousOwnerExit.evidence_sha256),'verification_recovery_in_progress');
  }
  const ownerIdentity=inert(nativeRecovery.owner_identity ?? {kind:'process_local_nonce',pid:process.pid,nonce:LOCAL_RECOVERER_NONCE});
  requireThat(ownerIdentity && !Array.isArray(ownerIdentity) && typeof ownerIdentity==='object' && Buffer.byteLength(JSON.stringify(ownerIdentity))<=8192,'verification_recovery_owner_invalid');
  const reservationToken=crypto.randomBytes(32).toString('hex');
  const reserved=mutate(context,(loc,a)=>{
    requireThat(a && a.attempt_id===snapshot.attempt_id && a.generation===snapshot.generation && a.revision===snapshot.revision,'verification_control_conflict');
    requireThat(!a.recovery || a.recovery.status!=='active' || previousOwnerExit!==null,'verification_recovery_in_progress');
    a.stop_reason ||= 'failure';
    a.phase='cleanup_pending';a.cleanup.status='pending';a.cleanup.attempts++;
    a.recovery={ordinal:(a.recovery?.ordinal??0)+1,recovery_id:crypto.randomBytes(16).toString('hex'),token_sha256:hash(reservationToken),
      owner_identity:ownerIdentity,started_at:now(),status:'active',reason_code:null};
    return changed(loc,a);
  });
  const recoveryCheck=a=>{
    requireThat(a && a.attempt_id===reserved.attempt_id && a.generation===reserved.generation && a.claimed &&
      a.recovery?.recovery_id===reserved.recovery.recovery_id && a.recovery.status==='active' &&
      a.recovery.token_sha256===hash(reservationToken),'verification_control_conflict');
    const binding=value=>{if(value===null)return null;const {cleanup_receipt,...immutable}=value;return immutable;};
    // A late trusted empty-container receipt is append-only evidence; its
    // arrival cannot invalidate the reservation or replace native ownership.
    requireThat(same(binding(a.containment),binding(reserved.containment)),'verification_control_conflict');
  };
  try {
    const proof=inert(nativeRecovery(publicAttempt(reserved)));
    requireThat(proof && typeof proof.then!=='function','verification_recovery_proof_invalid');
    return mutate(context,(loc,a)=>{
      recoveryCheck(a);
      // Exact process births and the complete native container proof are both
      // required. An arbitrary disappeared PID or elapsed lease is insufficient.
      requireThat(proof.method==='controller_only'?controllerOnly(a):a.processes.every(p=>p.pid!==null && (p.os_creation_time!==null || a.containment!==null && a.containment.spawn_ids.includes(p.spawn_id))),'verification_cleanup_unconfirmed');
      if(a.containment!==null) requireThat(proof.descriptor_sha256===a.containment.descriptor_sha256,'verification_process_identity_mismatch');
      if(proof.process_exits!==undefined) {
        requireThat(Array.isArray(proof.process_exits) && proof.process_exits.length<=128,'verification_recovery_proof_invalid');
        const seen=new Set();
        for(const exit of proof.process_exits) {
          const p=a.processes.find(p=>p.spawn_id===exit.spawn_id);
          const nativeMethod=['process_handle_signaled','windows_birth_absent','linux_pidfd_exit','linux_boot_birth_absent','linux_boot_birth_replaced','linux_namespace_init_exit'].includes(exit.method);
          requireThat(p && !seen.has(exit.spawn_id) && p.pid===exit.pid &&
            p.os_creation_time===(exit.os_creation_time??null) &&
            (p.os_creation_time!==null || p.process_nonce===exit.process_nonce) && nativeMethod,'verification_process_identity_mismatch');
          requireThat(exit.method!=='linux_namespace_init_exit' || a.containment?.backend==='linux_pid_namespace' && p.role==='authority' && a.containment.descriptor.worker?.pid===p.pid && proof.namespace_drained===true,'verification_process_identity_mismatch');
          // PID nonce alone is local ChildProcess evidence; native recovery may
          // use it only when bound to an authenticated containment descriptor.
          requireThat(p.os_creation_time!==null || a.containment!==null && a.containment.spawn_ids.includes(p.spawn_id),'verification_cleanup_unconfirmed');
          seen.add(exit.spawn_id);p.exit_observed=true;
        }
      }
      a.recovery.status='completed';
      return finishRecord(loc,a,{outcome:a.cancel.requested?'cancelled':'failed',cleanup_proof:proof});
    });
  } catch(error) {
    // A rejected proof is not a successful cleanup. Retain the coarse claim
    // and the work fence, but make a subsequent explicit recovery retry possible.
    try { mutate(context,(loc,a)=>{
      recoveryCheck(a);
      a.recovery.status='unconfirmed';
      const code=typeof error?.code==='string' && /^[a-z0-9_]{1,128}$/.test(error.code)?error.code:'verification_native_recovery_failed';
      a.recovery.reason_code=code;a.cleanup.status='unconfirmed';a.phase='cleanup_unconfirmed';changed(loc,a);
    }); } catch {}
    throw error;
  }
}

module.exports={SCHEMA,normalizeProfile,beginAttempt,readStatus,assertResourceAvailable,withResourceAvailable,updateAttempt,requestCancel,commitFinish,recoverAttempt,bindCleanupProof};
