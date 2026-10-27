'use strict';
// Read-only host observations plus disposable own publication attempts. This
// diagnostic does not alter AppArmor, capabilities, UID maps or shipping code.
const fs=require('fs'),path=require('path'),os=require('os');
const system=path.resolve(process.argv[2]);
const native=require(path.join(system,'tools/lib/verification-linux-namespace'));
const publication=require(path.join(system,'tools/lib/lock-publication'));
const locks=require(path.join(system,'tools/lib/contained-lock-manager'));
const policy=require(path.join(system,'tools/lib/lock-policy'));
function snapshot(){
 const raw=fs.readFileSync('/proc/self/status','utf8');
 const profile=fs.readFileSync('/proc/self/attr/current','utf8').trim();
 return {uid:process.getuid(),gid:process.getgid(),profile:profile==='unconfined'?'unconfined':profile.startsWith('unprivileged_userns')?'unprivileged_userns':'other',
  status:raw.split('\n').filter(s=>/^(Cap(Inh|Prm|Eff|Bnd|Amb)|NoNewPrivs|Seccomp):\s+[a-f0-9]+$/.test(s))};
}
function probe(){
 const root=fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(),'knowledge-boundary-probe-')));
 const version=path.join(root,'locks/v1'),release=path.join(version,'.release');
 const stage='publish-team-flow-01234567-89ab-4cde-8fed-0123456789ab.lock';
 const result={snapshot:snapshot(),filesystem_type_hex:fs.statfsSync(root).type.toString(16)};
 let lease;
 try {
  fs.mkdirSync(path.join(release,stage),{recursive:true});
  fs.writeFileSync(path.join(release,stage,'owner.json'),'{"complete":true}\n',{flag:'wx'});
  const p=publication.publishPreparedLock(root,stage,'team-flow.lock');lease=p.lease_id;
  result.raw_publication={status:p.status,native_error:p.native_error,published:p.published};
  if(lease){publication.closeOwnerLease(lease);lease=null;}
  try {
   const owned=locks.acquireContainedLock({context:{stateRoot:root},rootKind:'state',rootPath:root,
    lockName:'watch-maintenance',purpose:policy.LOCKS['watch-maintenance'].purpose});
   result.managed_publication={status:'acquired'};
   const released=owned.release();result.managed_publication.release_status=released.status;
  }catch(e){result.managed_publication={status:'failed',code:/^lock_[a-z_]{1,100}$/.test(e.code)?e.code:'unclassified',
   native_error:Number.isSafeInteger(e.native_error)?e.native_error:null,publication_may_have_completed:e.publication_may_have_completed===true};}
 } finally {
  if(lease)publication.closeOwnerLease(lease);
  if(path.dirname(root)!==fs.realpathSync(os.tmpdir())||!path.basename(root).startsWith('knowledge-boundary-probe-'))throw Error('cleanup_path');
  fs.rmSync(root,{recursive:true});
 }
 return result;
}
if(process.argv[3]==='--child'){
 process.send(probe());setInterval(()=>{},1000);
}else(async()=>{
 const result={schema_version:'knowledge-linux-boundary-diagnostic.v1',qualification:false,host:probe()};
 const helper=native.preparePackagedHelper({snapshot:true});
 const {worker,job}=native.spawnLinuxContainedWorker(process.execPath,[__filename,system,'--child'],
  {stdio:['ignore','ignore','pipe','ipc']},{preparedHelper:helper,lifetimeMs:20000,trustedAuthority:true});
 let timer;
 const report=new Promise((resolve,reject)=>{timer=setTimeout(()=>reject(Error('report_timeout')),10000);worker.once('message',resolve);worker.once('error',reject);});report.catch(()=>{});
 try{await job.ready;job.permit();await job.started;result.contained=await report;}
 catch(e){result.failure={code:/^[a-z_]{1,100}$/.test(e.code||'')?e.code:'diagnostic_failed',native_errno:e.native_errno};}
 finally{clearTimeout(timer);const closed=await job.close(10000);if(worker.connected)worker.disconnect();
  result.cleanup={status:closed.status,active_processes:closed.active_processes,namespace_drained:closed.namespace_drained};
  result.snapshot_cleanup=native.cleanupPreparedHelper(helper).status;}
 console.log(JSON.stringify(result));
 if(result.cleanup.status!=='completed'||result.snapshot_cleanup!=='completed')process.exitCode=1;
})().catch(()=>{console.log(JSON.stringify({schema_version:'knowledge-linux-boundary-diagnostic.v1',status:'diagnostic_failed',qualification:false}));process.exitCode=1;});
