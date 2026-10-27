'use strict';
// Portable protocol tests only. These mocks are not Windows kernel evidence.
const test=require('node:test');
const assert=require('node:assert/strict');
const cp=require('child_process');
const crypto=require('crypto');
const modulePath=require.resolve('../tools/lib/verification-windows-recovery');
const H='a'.repeat(64),birth='2026-10-20T10:00:00.0000000Z';
const descriptor={schema_version:'knowledge-windows-job.v1',backend:'windows_job_object',job_name:'Local\\KnowledgeVerification-'+H,
  host:{machine_guid_sha256:H,computer_name_sha256:H,user_sid_sha256:H,session_id:1},
  identities:{controller:{pid:201,os_creation_time:birth},keeper:{pid:202,os_creation_time:birth},worker:{pid:203,os_creation_time:birth}},source_sha256:H};
const hash=value=>crypto.createHash('sha256').update(JSON.stringify(value)).digest('hex');
function withTransport(transport,body) {
  const platform=Object.getOwnPropertyDescriptor(process,'platform'),root=process.env.SystemRoot,previous=cp.spawnSync,cached=require.cache[modulePath];
  try {
    Object.defineProperty(process,'platform',{...platform,value:'win32'});process.env.SystemRoot='/protocol-test-windows';
    cp.spawnSync=transport;delete require.cache[modulePath];
    return body(require(modulePath));
  } finally {
    Object.defineProperty(process,'platform',platform);if(root===undefined)delete process.env.SystemRoot;else process.env.SystemRoot=root;
    cp.spawnSync=previous;delete require.cache[modulePath];if(cached)require.cache[modulePath]=cached;
  }
}
function result(value,status=0) {return {status,signal:null,stdout:JSON.stringify(value)};}

test('a missing named Job yields explicit unconfirmed instead of zero-process success',()=>{
  withTransport((_file,_args,options)=>{
    const request=JSON.parse(options.input);assert.equal(request.action,'recover');assert.equal(request.descriptor.job_name,descriptor.job_name);
    return result({status:'unconfirmed',code:'recovery_job_reopen_unconfirmed'},2);
  },backend=>assert.throws(()=>backend.recoverContainer(descriptor),{code:'recovery_job_reopen_unconfirmed'}));
});

test('helper timeout preserves failure and has a separate generous transport allowance',()=>{
  withTransport((_file,args,options)=>{
    assert.equal(args[args.indexOf('-CleanupMs')+1],'45000');assert.equal(options.timeout,60000);
    assert.equal(options.killSignal,'SIGKILL');assert.equal(options.env.NODE_OPTIONS,undefined);assert.equal(options.env.NODE_PATH,undefined);
    return {status:null,signal:'SIGKILL',error:Object.assign(new Error('timeout'),{code:'ETIMEDOUT'}),stdout:'{"status":"completed"}'};
  },backend=>assert.throws(()=>backend.recoverContainer(descriptor,{cleanup_timeout_ms:45000}),{code:'verification_recovery_transport_unconfirmed'}));
});

test('a coherent result naming a different container or descriptor is rejected',()=>{
  for(const patch of [{descriptor_sha256:'0'.repeat(64)},{job_name:'Local\\KnowledgeVerification-'+'0'.repeat(64)}]) {
    withTransport(()=>result({status:'completed',descriptor_sha256:hash(descriptor),job_name:descriptor.job_name,...patch}),
      backend=>assert.throws(()=>backend.recoverContainer(descriptor),{code:'verification_process_identity_mismatch'}));
  }
});

test('persisted cleanup evidence is bound to both the original descriptor and the exact receipt',()=>{
  const receipt={status:'completed',method:'windows_job_object',active_processes:0,keeper_exited:true,worker_exited:true,descriptor_sha256:hash(descriptor)};
  receipt.evidence_sha256=hash(receipt);
  withTransport((_file,_args,options)=>{
    const request=JSON.parse(options.input);assert.equal(request.cleanup_receipt_sha256,hash(receipt));
    return result({status:'completed',descriptor_sha256:hash(descriptor),job_name:descriptor.job_name,
      container_proof_basis:'persisted_native_cleanup_receipt',cleanup_receipt_sha256:request.cleanup_receipt_sha256});
  },backend=>assert.equal(backend.recoverContainer(descriptor,{cleanup_receipt:receipt}).status,'completed'));
  const bad={...receipt,descriptor_sha256:'0'.repeat(64)};
  withTransport(()=>{throw new Error('native transport must not run');},
    backend=>assert.throws(()=>backend.recoverContainer(descriptor,{cleanup_receipt:bad}),{code:'verification_recovery_proof_invalid'}));
});

test('missing observer provenance is rejected before touching a local PID or Job',()=>{
  const bad={...descriptor};delete bad.host;
  withTransport(()=>{throw new Error('native transport must not run');},
    backend=>assert.throws(()=>backend.recoverContainer(bad),{code:'verification_recovery_descriptor_invalid'}));
});
