'use strict';
const path = require('path');
const crypto = require('crypto');
const { spawnSync } = require('child_process');
const { copyInertData } = require('./inert-data');

function fail(code) { throw Object.assign(new Error(code), {code}); }
function native(request, cleanupMs = 30000) {
  const root=process.env.SystemRoot || process.env.WINDIR;
  if(process.platform!=='win32' || !root || !path.isAbsolute(root)) fail('verification_native_recovery_unavailable');
  if(!Number.isSafeInteger(cleanupMs) || cleanupMs<1 || cleanupMs>3600000) fail('verification_profile_invalid');
  const env={...process.env};delete env.NODE_OPTIONS;delete env.NODE_PATH;
  const result=spawnSync(path.join(root,'System32/WindowsPowerShell/v1.0/powershell.exe'),
    ['-NoProfile','-NonInteractive','-File',path.join(__dirname,'verification-windows-recovery.ps1'),
      '-CleanupMs',String(cleanupMs),'-RecovererPid',String(process.pid)],
    {encoding:'utf8',input:JSON.stringify(copyInertData(request)),maxBuffer:65536,
      // Startup/transport has its own allowance. No millisecond wall-return
      // guarantee is claimed; a killed helper never supplies successful proof.
      timeout:cleanupMs+15000,killSignal:'SIGKILL',windowsHide:true,env});
  if(result.error || result.signal) fail('verification_recovery_transport_unconfirmed');
  let answer;try {answer=copyInertData(JSON.parse(result.stdout));}catch {fail('verification_recovery_proof_invalid');}
  if(answer.status==='unconfirmed' || result.status!==0) fail(/^[a-z0-9_]{1,128}$/.test(answer.code||'')?answer.code:'verification_native_recovery_failed');
  return answer;
}
function currentProcessIdentity() {return native({action:'identity'}).identity;}
function verifyProcessExit(identity) {return native({action:'verify_exit',identity:copyInertData(identity)});}
function queryScopeClosure(descriptor, { timeoutMs = 5000 } = {}) {
  try {
    descriptor = copyInertData(descriptor);
    const { readStableFile } = require('./stable-file');
    const source = readStableFile(path.resolve(__dirname, '..', '..'), path.join(__dirname, 'verification-windows-job.ps1'), { maxBytes: 1024 * 1024 });
    if (descriptor?.schema_version !== 'knowledge-windows-job.v1' || descriptor.backend !== 'windows_job_object' ||
        descriptor.source_sha256 !== crypto.createHash('sha256').update(source).digest('hex')) return { status: 'unconfirmed', method: 'windows_job_object', code: 'command_scope_pin_mismatch' };
    const descriptor_sha256 = crypto.createHash('sha256').update(JSON.stringify(descriptor)).digest('hex');
    const proof = native({ action: 'query_scope', descriptor, descriptor_sha256 }, Math.max(1, Math.floor(timeoutMs)));
    if (!['completed', 'active'].includes(proof.status) || proof.descriptor_sha256 !== descriptor_sha256 || proof.job_name !== descriptor.job_name) return { status: 'unconfirmed', method: 'windows_job_object', code: 'command_scope_proof_invalid' };
    return proof;
  } catch (error) { return { status: 'unconfirmed', method: 'windows_job_object', code: error.code || 'command_scope_query_unavailable' }; }
}
function recoverContainer(descriptor,{cleanup_timeout_ms=30000,cleanup_receipt=null}={}) {
  descriptor=copyInertData(descriptor);
  const host=descriptor?.host;
  if(descriptor?.schema_version!=='knowledge-windows-job.v1' || descriptor.backend!=='windows_job_object' ||
    !/^Local\\KnowledgeVerification-[a-f0-9]{64}$/.test(descriptor.job_name||'') || !/^[a-f0-9]{64}$/.test(descriptor.source_sha256||'') ||
    !host || !['machine_guid_sha256','computer_name_sha256','user_sid_sha256'].every(key=>/^[a-f0-9]{64}$/.test(host[key]||'')) ||
    !Number.isSafeInteger(host.session_id) || host.session_id<0 ||
    !['controller','keeper','worker'].every(role=>Number.isSafeInteger(descriptor.identities?.[role]?.pid) && descriptor.identities[role].pid>0 &&
      typeof descriptor.identities[role].os_creation_time==='string' && Number.isFinite(Date.parse(descriptor.identities[role].os_creation_time)))) fail('verification_recovery_descriptor_invalid');
  const descriptor_sha256=crypto.createHash('sha256').update(JSON.stringify(descriptor)).digest('hex');
  cleanup_receipt=copyInertData(cleanup_receipt);
  if(cleanup_receipt!==null) {
    const {evidence_sha256,...observed}=cleanup_receipt;
    if(cleanup_receipt.status!=='completed' || cleanup_receipt.method!=='windows_job_object' || cleanup_receipt.active_processes!==0 ||
      cleanup_receipt.keeper_exited!==true || cleanup_receipt.worker_exited!==true || cleanup_receipt.descriptor_sha256!==descriptor_sha256 ||
      evidence_sha256!==crypto.createHash('sha256').update(JSON.stringify(observed)).digest('hex')) fail('verification_recovery_proof_invalid');
  }
  const cleanup_receipt_sha256=cleanup_receipt===null?null:crypto.createHash('sha256').update(JSON.stringify(cleanup_receipt)).digest('hex');
  const proof=native({action:'recover',descriptor,descriptor_sha256,cleanup_receipt,cleanup_receipt_sha256},cleanup_timeout_ms);
  if(proof.descriptor_sha256!==descriptor_sha256 || proof.job_name!==descriptor.job_name ||
    (cleanup_receipt!==null && (proof.container_proof_basis!=='persisted_native_cleanup_receipt' || proof.cleanup_receipt_sha256!==cleanup_receipt_sha256))) fail('verification_process_identity_mismatch');
  return proof;
}
module.exports={currentProcessIdentity,verifyProcessExit,recoverContainer,queryScopeClosure};
