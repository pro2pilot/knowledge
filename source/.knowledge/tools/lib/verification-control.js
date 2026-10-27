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
const { acquireContainedLock, withContainedLock } = require('./contained-lock-manager');
const { LOCKS } = require('./lock-policy');

const LEGACY_SCHEMA = 'knowledge-verification-control.v1';
const PREVIOUS_SCHEMA = 'knowledge-verification-control.v2';
const TRANSCRIPT_PREVIOUS_SCHEMA = 'knowledge-verification-control.v3';
const LIFETIME_PREVIOUS_SCHEMA = 'knowledge-verification-control.v4';
const SCHEMA = 'knowledge-verification-control.v5';
const STORAGE_PROTOCOL = 'lifetime_lease.v1';
const INVOCATION_SCHEMA = 'knowledge-verification-invocation.v1';
const INVOCATION_TRANSCRIPT_SCHEMA = 'knowledge-verification-invocation-cleanup.v1';
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
const storageLeases = new Map();
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
function validInvocation(value) {
  // The durable ledger and the actual producer share one bounded immutable
  // shape. A transient Windows holder cannot become a recoverable invocation.
  return require('./verification-invocation').validInvocation(value);
}

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
  return { root, rootIdentity, directory, active: path.join(directory,'active.json'),
    initial: path.join(root,'maintenance','verification-control-initial.json') };
}
function requireStorageLease(loc, attempt) {
  if(attempt?.storage_protocol===STORAGE_PROTOCOL)
    requireThat(storageLeases.has(resourceKey(loc)),'verification_storage_lease_required');
}
function acquireStorageLease(context, options={}) {
  options=inert(options);
  requireThat(options && Object.keys(options).every(key=>key==='timeoutMs'),'verification_control_invalid');
  const loc=location(context),key=resourceKey(loc);
  requireThat(!storageLeases.has(key),'verification_storage_lease_already_held');
  const lease=acquireContainedLock({context,rootKind:'state',rootPath:loc.root,lockName:'verification-storage',
    purpose:LOCKS['verification-storage'].purpose,...(options.timeoutMs===undefined?{}:{timeoutMs:options.timeoutMs})});
  let active=true;
  const handle=Object.freeze({release(){
    if(!active)return false;
    // Revocation is irreversible even when retirement/cleanup fails. No
    // later control operation may rely on this spent in-process authority.
    active=false;storageLeases.delete(key);return lease.release();
  }});
  storageLeases.set(key,handle);return handle;
}
function withStorageLease(context, action, options={}) {
  requireThat(typeof action==='function','verification_control_invalid');
  const invoke=()=>{const result=action();requireThat(!result || typeof result.then!=='function','verification_storage_async_unsupported');return result;};
  if(storageLeases.has(resourceKey(location(context))))return invoke();
  const lease=acquireStorageLease(context,options);
  try{return invoke();}finally{lease.release();}
}
function withPriorStorageFence(context, action) {
  const loc=location(context),previous=load(loc);
  // Take the long lease before the short CAS mutex. The opposite lock order
  // could deadlock an old storage writer trying to finish its last write.
  return previous?.storage_protocol===STORAGE_PROTOCOL && !storageLeases.has(resourceKey(loc))
    ? withStorageLease(context,action) : action();
}
function physicalRead(loc,file) {
  try {
    assertSafeContainedPath(loc.root,file);
    const parents=[];
    let parent=loc.root;
    for(const part of ['',...path.relative(loc.root,path.dirname(file)).split(path.sep).filter(Boolean)]) {
      if(part)parent=path.join(parent,part);
      const stat=fs.lstatSync(parent,{bigint:true});
      requireThat(stat.isDirectory()&&!stat.isSymbolicLink(),'verification_control_unsafe');
      parents.push({path:parent,...identity(stat)});
    }
    const before = fs.lstatSync(file,{bigint:true});
    requireThat(before.isFile() && !before.isSymbolicLink() && before.nlink === 1n && before.size <= BigInt(MAX_BYTES),'verification_control_unsafe');
    const snapshotEqual = (a,b) => ['dev','ino','size','nlink','mtimeNs','ctimeNs'].every(k=>a[k]===b[k]);
    const fd = fs.openSync(file,fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0) | (fs.constants.O_NONBLOCK || 0));
    try {
      const opened = fs.fstatSync(fd,{bigint:true});
      requireThat(opened.isFile() && opened.nlink === 1n && opened.size <= BigInt(MAX_BYTES),'verification_control_unsafe');
      requireThat(snapshotEqual(before,opened),'verification_control_read_raced');
      const buffer=Buffer.alloc(MAX_BYTES+1);let size=0,count;
      do {count=fs.readSync(fd,buffer,size,buffer.length-size,null);size+=count;} while(count>0 && size<buffer.length);
      const bytes=buffer.subarray(0,size),after=fs.fstatSync(fd,{bigint:true}),live=fs.lstatSync(file,{bigint:true});
      requireThat(bytes.length <= MAX_BYTES && after.nlink<=1n && live.nlink===1n,'verification_control_unsafe');
      requireThat(after.nlink===1n,'verification_control_read_raced');
      requireThat(BigInt(bytes.length)===opened.size && snapshotEqual(opened,after) && snapshotEqual(after,live),'verification_control_read_raced');
      assertSafeContainedPath(loc.root,file);
      requireThat(same(identity(fs.lstatSync(loc.root,{bigint:true})),loc.rootIdentity),'verification_control_read_raced');
      for(const parent of parents) {
        const live=fs.lstatSync(parent.path,{bigint:true});
        requireThat(live.isDirectory()&&!live.isSymbolicLink()&&String(live.dev)===parent.dev&&String(live.ino)===parent.ino,'verification_control_read_raced');
      }
      return JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes));
    } finally { fs.closeSync(fd); }
  } catch (e) {
    // ENOENT anywhere in an existing control path is not silently swallowed by
    // status if active.json itself was physically present but raced away.
    if (['verification_control_unsafe','verification_control_read_raced'].includes(e.code)) throw e;
    if(e.code==='ENOENT')fail('verification_control_read_raced');
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
    a={...a,schema_version:TRANSCRIPT_PREVIOUS_SCHEMA,cleanup:{...a.cleanup,native_transcript:null,transcript_required:false}};
  if(a && a.schema_version===TRANSCRIPT_PREVIOUS_SCHEMA && exact(a,['schema_version','attempt_id','generation','revision','root_identity','request_sha256','owner_token_sha256','initiator','profile','phase','claimed','created_at','updated_at','cancel','stop_reason','runtime_observation','progress','progress_history','processes','cleanup','terminal','containment','recovery']))
    a={...a,schema_version:LIFETIME_PREVIOUS_SCHEMA,storage_protocol:null,startup_nonce_sha256:null};
  if(a && a.schema_version===LIFETIME_PREVIOUS_SCHEMA && exact(a,['schema_version','attempt_id','generation','revision','root_identity','request_sha256','owner_token_sha256','initiator','profile','phase','claimed','created_at','updated_at','cancel','stop_reason','runtime_observation','progress','progress_history','processes','cleanup','terminal','containment','recovery','storage_protocol','startup_nonce_sha256']) &&
    exact(a.cleanup,['status','attempts','evidence_sha256','native_transcript','transcript_required']))
    a={...a,schema_version:SCHEMA,invocation:null,cleanup:{...a.cleanup,invocation_transcript:null}};
  requireThat(exact(a,['schema_version','attempt_id','generation','revision','root_identity','request_sha256','owner_token_sha256','initiator','profile','phase','claimed','created_at','updated_at','cancel','stop_reason','runtime_observation','progress','progress_history','processes','cleanup','terminal','containment','recovery','storage_protocol','startup_nonce_sha256','invocation']),'verification_control_corrupt');
  requireThat(a.schema_version === SCHEMA && ID.test(a.attempt_id) && GENERATION.test(a.generation) && integer(a.revision,1) &&
    same(a.root_identity,loc.rootIdentity) && HASH.test(a.request_sha256) && HASH.test(a.owner_token_sha256) &&
    same(normalizeProfile(a.profile),a.profile) && PHASES.has(a.phase) && typeof a.claimed === 'boolean' && iso(a.created_at) && iso(a.updated_at) &&
    (a.storage_protocol===null ? a.startup_nonce_sha256===null : a.storage_protocol===STORAGE_PROTOCOL && HASH.test(a.startup_nonce_sha256)),'verification_control_corrupt');
  requireThat(a.invocation===null || a.storage_protocol===null && validInvocation(a.invocation),'verification_control_corrupt');
  if(a.invocation!==null)assertNativeProofPublicFields(a.invocation);
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
  requireThat(exact(a.cleanup,['status','attempts','evidence_sha256','native_transcript','transcript_required','invocation_transcript']) && ['not_started','pending','unconfirmed','confirmed'].includes(a.cleanup.status) && integer(a.cleanup.attempts) &&
    typeof a.cleanup.transcript_required==='boolean' &&
    (a.cleanup.evidence_sha256 === null || HASH.test(a.cleanup.evidence_sha256)),'verification_control_corrupt');
  if(a.containment!==null) {
    const c=a.containment;
    if(exact(c,['backend','descriptor_sha256','descriptor','spawn_ids'])) c.cleanup_receipt=null;
    requireThat(exact(c,['backend','descriptor_sha256','descriptor','spawn_ids','cleanup_receipt']) &&
      ['windows_job_object','linux_pid_namespace','darwin_private_ruid'].includes(c.backend) &&
      c.descriptor && !Array.isArray(c.descriptor) && typeof c.descriptor==='object' && c.descriptor.backend===c.backend &&
      HASH.test(c.descriptor_sha256) && hash(JSON.stringify(c.descriptor))===c.descriptor_sha256 &&
      Buffer.byteLength(JSON.stringify(c.descriptor))<=32768 && Array.isArray(c.spawn_ids) &&
      (c.spawn_ids.length>0 || c.backend==='darwin_private_ruid') &&
      c.spawn_ids.every((id,i)=>integer(id,1,a.processes.length) && (i===0 || c.spawn_ids[i-1]<id)),'verification_control_corrupt');
    if(c.backend==='darwin_private_ruid')requireThat(require('./verification-darwin-control').validateAttemptBinding(a,c),'verification_control_corrupt');
    if(c.cleanup_receipt!==null) {
      const receipt=c.cleanup_receipt,{evidence_sha256,...observed}=receipt;
      assertNativeProofPublicFields(receipt);
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
  if(a.cleanup.invocation_transcript!==null) validateInvocationTranscript(a,a.cleanup.invocation_transcript);
  if(a.phase === 'terminal') {
    requireThat(!a.cleanup.transcript_required || a.containment===null || a.cleanup.native_transcript!==null || a.cleanup.invocation_transcript!==null,'verification_control_corrupt');
    requireThat(!a.claimed && a.cleanup.status === 'confirmed' && exact(a.terminal,['outcome','ack_sha256']) && OUTCOMES.has(a.terminal.outcome),'verification_control_corrupt');
    requireThat(a.terminal.outcome === 'passed' ? !a.cancel.requested && a.stop_reason===null && HASH.test(a.terminal.ack_sha256) : a.terminal.ack_sha256 === null,'verification_control_corrupt');
    // A complete immutable outer scope may cover an inner spawn whose PID
    // was never returned. Preserve that unknown record rather than inventing
    // an exact process-exit observation. Such recovery can never release ACK.
    requireThat(a.processes.every(p=>p.pid!==null && p.exit_observed) ||
      a.cleanup.invocation_transcript!==null && a.terminal.outcome!=='passed','verification_control_corrupt');
  } else requireThat(a.claimed && a.terminal === null && a.cleanup.status !== 'confirmed','verification_control_corrupt');
  return a;
}
function present(loc,file) {
  try {fs.lstatSync(file);return true;}
  catch(error) {if(error.code!=='ENOENT')throw error;assertSafeContainedPath(loc.root,file,{allowMissing:true});return false;}
}
function initialOwnerMatches(a,b) {
  return ['attempt_id','generation','root_identity','request_sha256','owner_token_sha256','initiator','profile',
    'created_at','storage_protocol','startup_nonce_sha256','invocation'].every(key=>same(a[key],b[key]));
}
function readInitial(loc) {
  const a=validate(physicalRead(loc,loc.initial),loc);
  requireThat(a.schema_version===SCHEMA && a.revision===1 && a.claimed && a.phase==='reserved' &&
    !a.cancel.requested && a.stop_reason===null && a.processes.length===0 && a.containment===null && a.recovery===null &&
    a.cleanup.status==='not_started' && a.cleanup.attempts===0 && a.terminal===null,'verification_control_initial_corrupt');
  return a;
}
function load(loc) {
  // The initial journal is published before creating the control directory.
  // It is a complete claim, never an idle-state hint. Older writers do not
  // know this journal, so a different active owner is an explicit conflict.
  for(let n=0;n<3;n++)try {
    const hasActive=present(loc,loc.active),hasInitial=present(loc,loc.initial);
    const initial=hasInitial?readInitial(loc):null;
    if(hasActive) {
      const a=validate(physicalRead(loc,loc.active),loc);
      requireThat(!initial || initialOwnerMatches(a,initial),'verification_control_initial_conflict');
      return a;
    }
    if(initial) {
      // A concurrent cancellation/recovery may have advanced active.json
      // while this read consumed the immutable journal. Prefer its new row.
      if(present(loc,loc.active))continue;
      return initial;
    }
    if(present(loc,loc.directory))fail('verification_control_missing');
    return null;
  } catch(error) {
    if(!['verification_control_read_raced','verification_control_initial_conflict'].includes(error.code)||n===2)throw error;
  }
  fail('verification_control_read_raced');
}
function syncDirectory(loc,directory) {
  // Windows process-crash recovery is supported. Power-loss directory-entry
  // persistence is not inferred from a platform without this POSIX fsync.
  if(process.platform==='win32')return;
  assertSafeContainedPath(loc.root,directory);
  const before=fs.lstatSync(directory,{bigint:true});
  requireThat(before.isDirectory()&&!before.isSymbolicLink(),'verification_control_unsafe');
  const fd=fs.openSync(directory,fs.constants.O_RDONLY|(fs.constants.O_DIRECTORY||0)|(fs.constants.O_NOFOLLOW||0));
  try {
    requireThat(same(identity(fs.fstatSync(fd,{bigint:true})),identity(before)),'verification_control_read_raced');
    fs.fsyncSync(fd);
    requireThat(same(identity(fs.lstatSync(directory,{bigint:true})),identity(before)),'verification_control_read_raced');
    assertSafeContainedPath(loc.root,directory);
    requireThat(same(identity(fs.lstatSync(loc.root,{bigint:true})),loc.rootIdentity),'verification_control_read_raced');
  } finally {fs.closeSync(fd);}
}
function publishInitial(loc,a) {
  requireThat(!present(loc,loc.initial) && !present(loc,loc.active) && !present(loc,loc.directory),'verification_control_initial_conflict');
  ensureContainedDir(loc.root,path.dirname(loc.initial));
  syncDirectory(loc,loc.root);
  writeJsonAtomicContained(loc.initial,a,loc.root);
  syncDirectory(loc,path.dirname(loc.initial));
  requireThat(same(readInitial(loc),a),'verification_control_readback_failed');
}
function retireInitial(loc,a) {
  if(!present(loc,loc.initial))return;
  const before=fs.lstatSync(loc.initial,{bigint:true}),initial=readInitial(loc);
  requireThat(initialOwnerMatches(a,initial),'verification_control_initial_conflict');
  // The full active row must be durable before removing the only pre-directory
  // claim. Cancellation/recovery may have legitimately advanced that row.
  syncDirectory(loc,loc.directory);
  // Persist the newly-created control directory entry in its parent before
  // the sole pre-directory claim can disappear, including a crash before the
  // final parent fsync which persists journal removal.
  syncDirectory(loc,path.dirname(loc.directory));
  const current=fs.lstatSync(loc.initial,{bigint:true});
  requireThat(['dev','ino','size','nlink','mtimeNs','ctimeNs'].every(key=>before[key]===current[key]),'verification_control_read_raced');
  assertSafeContainedPath(loc.root,loc.initial);
  fs.unlinkSync(loc.initial);
  syncDirectory(loc,path.dirname(loc.initial));
}
function write(loc,a) {
  validate(a,loc);
  requireThat(Buffer.byteLength(JSON.stringify(a)) <= MAX_BYTES,'verification_control_oversized');
  ensureContainedDir(loc.root,loc.directory);
  writeJsonAtomicContained(loc.active,a,loc.root);
  requireThat(same(load(loc),a),'verification_control_readback_failed');
  retireInitial(loc,a);
}
function mutate(context, fn, deadline=null) {
  const loc=location(context);
  requireThat(!resourceScopes.has(resourceKey(loc)),'verification_resource_busy');
  const timeoutMs=deadline===null?5000:Math.min(5000,Math.floor(Number(deadline-process.hrtime.bigint())/1e6));
  requireThat(timeoutMs>0,'verification_recovery_budget_exceeded');
  return withContainedLock({context,rootKind:'state',rootPath:loc.root,lockName:'verification-control',purpose:LOCKS['verification-control'].purpose,timeoutMs},()=>fn(loc,load(loc)));
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
  requireThat(options.storage_protocol===undefined || options.storage_protocol===STORAGE_PROTOCOL,'verification_storage_protocol_invalid');
  requireThat(options.storage_protocol===STORAGE_PROTOCOL ? HASH.test(options.startup_nonce_sha256) :
    options.startup_nonce_sha256===undefined,'verification_startup_nonce_invalid');
  requireThat(options.invocation===undefined || options.storage_protocol===undefined && validInvocation(options.invocation),
    'verification_invocation_invalid');
  if(options.invocation!==undefined)assertNativeProofPublicFields(options.invocation);
  requireStorageLease(location(context),{storage_protocol:options.storage_protocol});
  const profile=normalizeProfile(options.profile);
  return withPriorStorageFence(context,()=>mutate(context,(loc,a)=>{
    if(a?.claimed) fail('verification_recovery_required','An active verification owns this state root; inspect status/cancel/recover.');
    requireStorageLease(loc,a);
    if(a) {
      const archived=path.join(loc.directory,'attempts',a.attempt_id+'.json');
      ensureContainedDir(loc.root,path.dirname(archived));
      if(fs.existsSync(archived)) requireThat(same(validate(physicalRead(loc,archived),loc),a),'verification_control_corrupt');
      else writeJsonAtomicContained(archived,a,loc.root);
    }
    const first=a===null;
    const token=crypto.randomBytes(32).toString('hex'),at=now();
    a={schema_version:SCHEMA,attempt_id:'VAT-'+crypto.randomBytes(16).toString('hex'),generation:crypto.randomBytes(16).toString('hex'),revision:1,root_identity:loc.rootIdentity,
      request_sha256:options.request_sha256,owner_token_sha256:hash(token),initiator:{pid:process.pid,agent_id:/^[A-Za-z0-9_.-]{1,128}$/.test(process.env.KNOWLEDGE_AGENT_ID||'')?process.env.KNOWLEDGE_AGENT_ID:null,host_sha256:hash(os.hostname()),process_creation_time:null},profile,phase:'reserved',claimed:true,created_at:at,updated_at:at,
      cancel:{requested:false,reason_code:null,at:null},stop_reason:null,runtime_observation:null,progress:{sequence:0,milestone:null,ordinal:0,evidence_sha256:null,at:null},progress_history:[],processes:[],cleanup:{status:'not_started',attempts:0,evidence_sha256:null,native_transcript:null,transcript_required:true,invocation_transcript:null},terminal:null,containment:null,recovery:null,storage_protocol:options.storage_protocol??null,startup_nonce_sha256:options.startup_nonce_sha256??null,invocation:options.invocation??null};
    if(first)publishInitial(loc,a);
    write(loc,a);
    return {attempt:publicAttempt(a),owner:{attempt_id:a.attempt_id,generation:a.generation,token}};
  }));
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
  return withPriorStorageFence(context,()=>mutate(context,(_loc,a)=>{
    if(a?.claimed)fail('verification_recovery_required');
    requireStorageLease(_loc,a);
    resourceScopes.add(key);
    try{return invoke();}finally{resourceScopes.delete(key);}
  }));
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
    requireStorageLease(loc,a);
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
        ['windows_job_object','linux_pid_namespace','darwin_private_ruid'].includes(descriptor.backend) && Buffer.byteLength(JSON.stringify(descriptor))<=32768 &&
        Array.isArray(ids) && (ids.length>0 || descriptor.backend==='darwin_private_ruid') && ids.every((id,i)=>integer(id,1,a.processes.length) && (i===0 || ids[i-1]<id)),'verification_containment_invalid');
      a.containment={backend:descriptor.backend,descriptor_sha256:hash(JSON.stringify(descriptor)),descriptor,spawn_ids:ids,cleanup_receipt:null};
      if(descriptor.backend==='darwin_private_ruid')requireThat(require('./verification-darwin-control').validateAttemptBinding(a),'verification_containment_invalid');
    } else if(event.type==='darwin_authority_bound') {
      requireThat(!a.cancel.requested && !a.stop_reason && a.cleanup.status==='not_started' &&
        a.containment?.backend==='darwin_private_ruid' && a.containment.descriptor.authority_identity===null &&
        a.processes.length===0 && a.containment.spawn_ids.length===0,'verification_stopped');
      const descriptor=inert(event.descriptor),previous=a.containment.descriptor;
      const bridge=require('./verification-darwin-control');
      requireThat(bridge.validateDescriptor(descriptor) && descriptor.authority_identity!==null &&
        same(descriptor.scope,previous.scope) && same(descriptor.controller_identity,previous.controller_identity) &&
        descriptor.authority_identity.birth.pid===event.pid && (event.process_nonce??event.logical_nonce)===a.generation &&
        HASH.test(event.executable_sha256),'verification_containment_invalid');
      a.processes=[{spawn_id:1,role:'authority',pid:event.pid,os_creation_time:null,process_nonce:a.generation,
        executable_sha256:event.executable_sha256,exit_observed:false}];
      a.containment={backend:descriptor.backend,descriptor_sha256:hash(JSON.stringify(descriptor)),descriptor,
        spawn_ids:[1],cleanup_receipt:null};
      requireThat(bridge.validateAttemptBinding(a),'verification_containment_invalid');
    } else if(event.type==='spawn_intent') {
      requireThat(!a.cancel.requested && !a.stop_reason && a.cleanup.status==='not_started','verification_stopped');
      requireThat(a.containment?.backend!=='darwin_private_ruid','verification_spawn_invalid');
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
  // Older normal receipts omit inference fields. If present, the fields must
  // be booleans; false-looking strings/null are not native observations.
  if(proof.namespace_drained!==true || typeof proof.init_reaped!=='boolean' ||
    ['init_exit_inferred','init_release_inferred'].some(key=>Object.hasOwn(proof,key) && typeof proof[key]!=='boolean')) return false;
  if(proof.init_exit_observed===true) {
    if(proof.init_exit_inferred===true || proof.init_release_inferred===true) return false;
    return proof.init_reaped===true || allowInference && proof.init_exit_basis==='linux_pidfd_exit' && proof.init_reap_basis==='kernel_namespace_init_final_exit';
  }
  return allowInference && proof.init_exit_observed===false && proof.init_exit_inferred===true && proof.init_reaped===false && proof.init_release_inferred===true &&
    ['linux_boot_birth_absent','linux_boot_birth_replaced'].includes(proof.init_exit_basis) && proof.init_reap_basis==='kernel_namespace_init_final_exit';
}
function validNativeContainerProof(a,proof) {
  if(proof?.method==='darwin_private_ruid') {
    const bridge=require('./verification-darwin-control');
    return proof.attempt_id===a.attempt_id && proof.generation===a.generation &&
      a.containment?.backend==='darwin_private_ruid' && proof.descriptor_sha256===a.containment.descriptor_sha256 &&
      HASH.test(proof.evidence_sha256) && bridge.validateAttemptBinding(a) &&
      bridge.validateProof(proof,a.containment.descriptor,{allowRecovery:a.recovery!==null}) &&
      (proof.proof_kind!=='normal_current' || proof.authority_exit.process_nonce===a.generation);
  }
  return proof && proof.attempt_id===a.attempt_id && proof.generation===a.generation &&
    proof.status==='completed' && ['windows_job_object','linux_pid_namespace'].includes(proof.method) && proof.active_processes===0 &&
    (a.containment===null ? proof.method==='windows_job_object' : proof.method===a.containment.backend && proof.descriptor_sha256===a.containment.descriptor_sha256 && proof.worker_exited===true) &&
    proof.keeper_exited===true && (proof.method!=='linux_pid_namespace' || proof.worker_exited===true && namespaceFinality(proof,a.recovery!==null)) && HASH.test(proof.evidence_sha256);
}
function confirmedCleanup(a,proof) {
  proof=inert(proof);
  if(!proof || proof.attempt_id!==a.attempt_id || proof.generation!==a.generation)return false;
  if(proof.method==='no_processes_started')return a.processes.length===0 && a.containment===null;
  if(proof.method==='controller_only')return proof.status==='completed' && HASH.test(proof.evidence_sha256) && controllerOnly(a);
  return validNativeContainerProof(a,proof) && (a.processes.length>0 ||
    proof.method==='darwin_private_ruid' && proof.proof_kind==='recovery_observation' && a.containment.descriptor.authority_identity===null) &&
    a.processes.every(p=>p.pid!==null && p.exit_observed);
}

// Preserve the exact native return before adding control-plane bindings. The
// digest covers both; callers must not hash a different, unbound projection.
function bindCleanupProof(owner,nativeProof) {
  const observed=inert(nativeProof);
  requireThat(observed && typeof observed==='object' && !Array.isArray(observed),'verification_cleanup_unconfirmed');
  assertNativeProofPublicFields(observed);
  const proof={...observed,attempt_id:owner.attempt_id,generation:owner.generation,native_return:observed};
  delete proof.evidence_sha256;
  proof.evidence_sha256=hash(JSON.stringify(proof));
  return proof;
}

// Fixed native adapters return process/container facts. Reject capability and
// credential field names at every persistence boundary, including the earlier
// normal receipt. This is a field policy, not a detector for arbitrary secrets.
function assertNativeProofPublicFields(value,depth=0) {
  requireThat(depth<=32,'verification_control_corrupt');
  if(value && typeof value==='object') for(const [key,item] of Object.entries(value)) {
    const normalized=key.replace(/[^a-z0-9]/gi,'').toLowerCase();
    requireThat(!['token','ownertoken','controltoken','capabilitytoken','privatekey','privatekeypem','signingprivatekey',
      'accesstoken','refreshtoken','bearertoken','apikey','authorization','password','clientsecret'].includes(normalized),
      'verification_native_transcript_sensitive');
    assertNativeProofPublicFields(item,depth+1);
  }
}

function validInvocationProof(invocation,proof) {
  if(!validInvocation(invocation) || !proof || proof.status!=='completed' ||
    proof.scope_sha256!==invocation.scope_sha256 || proof.method!==invocation.scope.backend || proof.active_processes!==0) return false;
  if(proof.method==='linux_pid_namespace')return proof.namespace_drained===true &&
    proof.descriptor_sha256===hash(JSON.stringify(invocation.scope.descriptor)) &&
    ['linux_pidfd_exit','linux_boot_birth_absent','linux_boot_birth_replaced'].includes(proof.init_exit_basis) &&
    typeof proof.process_reaped==='boolean' && typeof proof.release_inferred==='boolean';
  return proof.root_exited===true && proof.admission_sealed===true && proof.current_host_verified===true &&
    (proof.basis==='signed_terminal_receipt' && HASH.test(proof.receipt_sha256) && ['primary','secondary'].includes(proof.holder_role) ||
     proof.basis==='current_kernel_job_zero' && ['exact_birth_replaced','exact_handle_signaled','exact_pid_absent'].includes(proof.root_basis));
}
function validateInvocationTranscript(a,t) {
  requireThat(exact(t,['schema_version','attempt_id','generation','invocation_sha256','scope_sha256','recorded_at','payload_sha256','payload']) &&
    t.schema_version===INVOCATION_TRANSCRIPT_SCHEMA && t.attempt_id===a.attempt_id && t.generation===a.generation &&
    a.invocation!==null && t.invocation_sha256===hash(JSON.stringify(a.invocation)) &&
    t.scope_sha256===a.invocation.scope_sha256 && iso(t.recorded_at) && HASH.test(t.payload_sha256) &&
    exact(t.payload,['native_return']) && hash(JSON.stringify(t.payload))===t.payload_sha256 &&
    Buffer.byteLength(JSON.stringify(t))<=MAX_TRANSCRIPT_BYTES && validInvocationProof(a.invocation,t.payload.native_return),
    'verification_control_corrupt');
  requireThat(a.phase==='terminal' && a.terminal?.outcome!=='passed','verification_control_corrupt');
  assertNativeProofPublicFields(t.payload);
}

// A fixed readonly provider proves closure of the writer boundary saved in
// the very first claim. It never accepts a supplied proof/PID/force callback.
// Whole-boundary closure is irreversible; after it, the final short CAS may
// preserve unknown inner spawn intents without inventing individual exits.
function recoverInvocation(context,input) {
  const started=process.hrtime.bigint();input=inert(input);
  requireThat(input && Object.keys(input).every(key=>['attempt_id','generation','invocation_nonce_sha256','invocation_scope_sha256','deadline_ns','recovery_reason'].includes(key)),
    'verification_control_invalid');
  requireThat(input.recovery_reason===undefined || ['cancelled','work_timeout','progress_timeout','failure'].includes(input.recovery_reason),
    'verification_control_invalid');
  let requestedDeadline=null;
  if(input.deadline_ns!==undefined) {
    requireThat(typeof input.deadline_ns==='string' && /^\d{1,32}$/.test(input.deadline_ns),'verification_clock_invalid');
    requestedDeadline=BigInt(input.deadline_ns);
    requireThat(started<requestedDeadline,'verification_recovery_budget_exceeded');
  }
  const loc=location(context),snapshot=load(loc);
  requireThat(snapshot && validInvocation(snapshot.invocation),'verification_attempt_mismatch');
  const selectedByNonce=input.invocation_nonce_sha256!==undefined || input.invocation_scope_sha256!==undefined;
  if(selectedByNonce)requireThat(HASH.test(input.invocation_nonce_sha256) && HASH.test(input.invocation_scope_sha256) &&
    input.invocation_nonce_sha256===snapshot.invocation.nonce_sha256 && input.invocation_scope_sha256===snapshot.invocation.scope_sha256,
    'verification_attempt_mismatch');
  requireThat(selectedByNonce && input.attempt_id===undefined && input.generation===undefined ||
    input.attempt_id===snapshot.attempt_id && input.generation===snapshot.generation,'verification_attempt_mismatch');
  if(!snapshot.claimed)return {status:'already_terminal',ack_released:false,attempt:publicAttempt(snapshot)};
  requireThat(snapshot.recovery?.status!=='active','verification_recovery_in_progress');
  const profileDeadline=started+BigInt(snapshot.profile.cleanup_budget_ms)*1000000n;
  const deadline=requestedDeadline!==null && requestedDeadline<profileDeadline ? requestedDeadline : profileDeadline;
  const remaining=()=>Math.floor(Number(deadline-process.hrtime.bigint())/1e6);
  requireThat(remaining()>0,'verification_recovery_budget_exceeded');
  const observed=inert(require('./command-scope-proof').queryScopeClosure(inert(snapshot.invocation.scope),
    {timeoutMs:Math.min(600000,remaining())}));
  requireThat(remaining()>0,'verification_recovery_budget_exceeded');
  assertNativeProofPublicFields(observed);
  if(!validInvocationProof(snapshot.invocation,observed))return {status:'requires_native_recovery',ack_released:false,
    reason:observed?.status==='active'?'verification_invocation_scope_active':observed?.code||'verification_invocation_scope_unconfirmed',
    invocation_observation:observed,attempt:publicAttempt(snapshot)};
  const value=mutate(context,(current,a)=>{
    requireThat(remaining()>0,'verification_recovery_budget_exceeded');
    requireThat(a && a.attempt_id===snapshot.attempt_id && a.generation===snapshot.generation &&
      same(a.invocation,snapshot.invocation),'verification_attempt_mismatch');
    if(!a.claimed)return {status:'already_terminal',ack_released:false,attempt:publicAttempt(a)};
    requireThat(a.recovery?.status!=='active','verification_recovery_in_progress');
    const payload={native_return:observed};
    a.cleanup.invocation_transcript={schema_version:INVOCATION_TRANSCRIPT_SCHEMA,attempt_id:a.attempt_id,generation:a.generation,
      invocation_sha256:hash(JSON.stringify(a.invocation)),scope_sha256:a.invocation.scope_sha256,
      recorded_at:now(),payload_sha256:hash(JSON.stringify(payload)),payload};
    // An outcome request is not proof of process death. Apply it only after
    // fresh whole-scope closure and the exact invocation CAS.
    if(input.recovery_reason==='cancelled' && !a.cancel.requested)
      a.cancel={requested:true,reason_code:'user_requested',at:now()};
    a.stop_reason ||= input.recovery_reason==='cancelled'?'failure':input.recovery_reason||'failure';
    const outcome=a.cancel.requested?'cancelled':['work_timeout','progress_timeout'].includes(a.stop_reason)?'timed_out':'failed';
    a.phase='terminal';a.claimed=false;a.cleanup.status='confirmed';a.cleanup.attempts++;
    if(a.cleanup.native_transcript===null)a.cleanup.evidence_sha256=a.cleanup.invocation_transcript.payload_sha256;
    if(a.recovery!==null)a.recovery.status='completed';
    a.terminal={outcome,ack_sha256:null};changed(current,a);
    return {status:outcome,ack_released:false,attempt:publicAttempt(a)};
  },deadline);
  // A late write can already have become durable, but it cannot manufacture a
  // timely result. The caller retains the exact selector for a later readback.
  requireThat(remaining()>0,'verification_recovery_budget_exceeded');
  return value;
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
  assertNativeProofPublicFields(t.payload);
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
  requireThat(input.outcome!=='passed' || input.cleanup_proof.method!=='darwin_private_ruid' ||
    input.cleanup_proof.proof_kind==='normal_current' && input.cleanup_proof.proof_current===true &&
    input.cleanup_proof.cleanup_only===false,'verification_cleanup_unconfirmed');
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
    requireStorageLease(loc,a);
    if(!a.claimed)return {status:a.terminal.outcome,ack_released:a.terminal.outcome==='passed',attempt:publicAttempt(a)};
    requireThat(a.recovery===null,'verification_recovery_in_progress');
    return finishRecord(loc,a,input);
  });
}
function recoverAttempt(context,input,nativeRecovery=null) {
  input=inert(input);const loc=location(context),snapshot=load(loc);
  requireThat(snapshot && input && snapshot.attempt_id===input.attempt_id && snapshot.generation===input.generation,'verification_attempt_mismatch');
  if(snapshot.invocation!==null)return recoverInvocation(context,input);
  if(!snapshot.claimed)return {status:'already_terminal',attempt:publicAttempt(snapshot)};
  requireStorageLease(loc,snapshot);
  // Only existing exact-handle exit evidence can recover this narrow case.
  // Any authority/keeper/unknown spawn intent still needs a native adapter.
  if(typeof nativeRecovery!=='function') {
    requireThat(snapshot.recovery?.status!=='active','verification_recovery_in_progress');
    if(snapshot.processes.length===0 && snapshot.containment===null) {
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
          const nativeMethod=['process_handle_signaled','windows_birth_absent','linux_pidfd_exit','linux_boot_birth_absent','linux_boot_birth_replaced','linux_namespace_init_exit','darwin_registered_authority_exit'].includes(exit.method);
          requireThat(p && !seen.has(exit.spawn_id) && p.pid===exit.pid &&
            p.os_creation_time===(exit.os_creation_time??null) &&
            (p.os_creation_time!==null || p.process_nonce===exit.process_nonce) && nativeMethod,'verification_process_identity_mismatch');
          requireThat(exit.method!=='linux_namespace_init_exit' || a.containment?.backend==='linux_pid_namespace' && p.role==='authority' && a.containment.descriptor.worker?.pid===p.pid && proof.namespace_drained===true,'verification_process_identity_mismatch');
          requireThat(exit.method!=='darwin_registered_authority_exit' || a.containment?.backend==='darwin_private_ruid' &&
            p.role==='authority' && a.containment.descriptor.authority_identity?.birth.pid===p.pid &&
            proof.proof_kind==='recovery_observation','verification_process_identity_mismatch');
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

module.exports={SCHEMA,STORAGE_PROTOCOL,INVOCATION_SCHEMA,acquireStorageLease,withStorageLease,normalizeProfile,beginAttempt,readStatus,assertResourceAvailable,withResourceAvailable,updateAttempt,requestCancel,commitFinish,recoverAttempt,recoverInvocation,bindCleanupProof};
