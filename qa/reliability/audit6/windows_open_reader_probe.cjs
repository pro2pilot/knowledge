'use strict';
// Observe the platform restriction behind the POSIX unlink fixture without
// weakening the runtime or changing atomic-write retry/deadline settings.
const fs=require('node:fs'),path=require('node:path'),os=require('node:os'),assert=require('node:assert/strict');
assert.equal(process.platform,'win32');
const system=path.resolve(process.argv[2]);
const control=require(path.join(system,'tools/lib/verification-control.js'));
const store=require(path.join(system,'tools/lib/json-store.js'));
const clean=require(path.join(system,'tools/lib/strict-temp-cleanup.js'));
const root=fs.mkdtempSync(path.join(os.tmpdir(),'knowledge-reader-probe-'));
const context={stateRoot:root},report={schema_version:'knowledge-windows-open-reader-observation.v1',status:'FAIL',platform:process.platform,architecture:process.arch,root,release_qualified:false};
let fd=null,owner;
try{
 const started=control.beginAttempt(context,{request_sha256:'a'.repeat(64),profile:{work_budget_ms:10000,no_progress_ms:3000,cleanup_budget_ms:2000}});owner=started.owner;
 const file=path.join(root,'maintenance/verification-control/active.json');
 const before=JSON.parse(fs.readFileSync(file,'utf8'));
 control.requestCancel(context,{attempt_id:owner.attempt_id,generation:owner.generation});
 const next=JSON.parse(fs.readFileSync(file,'utf8'));store.writeJsonAtomicContained(file,before,root);
 const unchanged=fs.readFileSync(file);
 fd=fs.openSync(file,fs.constants.O_RDONLY|(fs.constants.O_NOFOLLOW||0)|(fs.constants.O_NONBLOCK||0));
 report.opened_nlink=String(fs.fstatSync(fd,{bigint:true}).nlink);
 let caught;const observed=[];const startedNs=process.hrtime.bigint();
 try{store.writeJsonAtomicContained(file,next,root,{hooks:{renameSync(from,to){try{return fs.renameSync(from,to);}catch(e){observed.push({code:e.code,syscall:e.syscall});throw e;}}}});}catch(e){caught=e;}
 report.held_reader_write={elapsed_ms:Number(process.hrtime.bigint()-startedNs)/1e6,error:caught?{code:caught.code,os_code:caught.os_code,attempts:caught.attempts,operation:caught.operation,cause_code:caught.cause?.code}:null,rename_attempt_errors:observed};
 assert(caught,'this diagnostic expected the observed Windows sharing refusal');
 assert.equal(caught.code,'atomic_write_retry_exhausted');assert(['EPERM','EACCES','EBUSY'].includes(caught.os_code));assert.equal(caught.attempts,6);assert.equal(observed.length,6);
 assert(fs.readFileSync(file).equals(unchanged),'failed atomic publication changed the old committed bytes');
 fs.closeSync(fd);fd=null;report.owned_read_handle_closed=true;
 store.writeJsonAtomicContained(file,next,root);
 const status=control.readStatus(context);assert.equal(status.attempt.cancel.requested,true);assert.equal(status.attempt.revision,next.revision);
 report.publication_after_close={cancel_requested:status.attempt.cancel.requested,revision:status.attempt.revision,status:status.status};
 const terminal=control.recoverAttempt(context,{attempt_id:owner.attempt_id,generation:owner.generation});assert.equal(terminal.status,'cancelled');assert.equal(terminal.ack_released,false);
 report.no_process_recovery={status:terminal.status,ack_released:terminal.ack_released};
 report.status='PASS_WINDOWS_READER_SHARING_OBSERVATION';
}catch(e){report.error={code:e.code||null,message:e.message,stack:e.stack};process.exitCode=1;}
finally{
 if(fd!==null){fs.closeSync(fd);fd=null;report.owned_read_handle_closed=true;}
 try{clean.removeTempDirStrict(root);report.fixture_removed=!fs.existsSync(root);}catch(e){report.cleanup_error={code:e.code,message:e.message};report.status='FAIL';process.exitCode=1;}
 process.stdout.write(JSON.stringify(report,null,2)+'\n');
}
