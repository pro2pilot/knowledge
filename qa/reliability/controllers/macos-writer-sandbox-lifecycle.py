#!/usr/bin/env python3
"""Fixed-probe native writer profile qualification; NOT shipping Flow evidence.

The sole package replacement is declared and hashed. The probe is launched by
the shipping native guardian with root custody before permit and the shipping
workspace.v1 original-UID write profile. Another process replaces the checked
directory with a symlink before the actual attempted write.
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time

CASE = 'original_uid_writer_symlink_substitution'
STATUS = 'PASS_PHYSICAL_MACOS_WRITER_SANDBOX'
DERIVATION = 'exact runtime copy with fixed QA macos-command-worker replacement and compiled source-bound addon'

WORKER = r"""'use strict';
const fs=require('node:fs'),net=require('node:net'),path=require('node:path');
const parent=new net.Socket({fd:3,readable:true,writable:false});
parent.on('end',()=>process.exit(1));parent.on('error',()=>process.exit(1));parent.resume();
process.on('disconnect',()=>process.exit(1));
const send=value=>new Promise((resolve,reject)=>process.send(value,error=>error?reject(error):resolve()));
let used=false,request;
process.on('message',async message=>{try{
 if(message.type==='start'&&!used){used=true;
  if(message.role==='authority'){
   const input=message.input;const reply=(await require('./verification-darwin-session').rpc(input.config,
    {op:'register_authority',...input.auth},{limitMs:20000})).reply;
   await send({type:'registered',reply});return;
  }
  if(message.role!=='probe')throw Object.assign(new Error(),{code:'qa_writer_role_invalid'});
  request=message;const dir=path.join(request.root,'race');
  fs.writeFileSync(path.join(request.root,'inside-control'),'inside',{mode:0o600});
  const stat=fs.lstatSync(dir,{bigint:true});if(!stat.isDirectory()||stat.isSymbolicLink())throw Object.assign(new Error(),{code:'qa_writer_directory_invalid'});
  await send({type:'checked',uid:process.getuid(),pid:process.pid,checked_directory:{dev:String(stat.dev),ino:String(stat.ino)}});return;
 }
 if(message.type==='continue'&&request){
  let outside_errno=null;try{fs.writeFileSync(path.join(request.root,'race','canary'),'escaped');}
  catch(error){outside_errno=error.code;}
  await send({type:'probe',uid:process.getuid(),pid:process.pid,inside_control:fs.readFileSync(path.join(request.root,'inside-control'),'utf8')==='inside',outside_errno});return;
 }
 if(message.type==='finish'&&request){await send({type:'finished'});process.exit(0);}
 throw Object.assign(new Error(),{code:'qa_writer_protocol_invalid'});
}catch(error){await send({type:'error',code:/^[A-Za-z0-9_]{1,100}$/.test(error.code||'')?error.code:'qa_writer_failed'}).catch(()=>{});process.exit(1);}});
"""

CALLER = r"""'use strict';
const fs=require('node:fs'),path=require('node:path'),assert=require('node:assert/strict'),crypto=require('node:crypto');
const q=JSON.parse(fs.readFileSync(0,'utf8'));
const sessions=require(path.join(q.source,'tools/lib/macos-workspace-session')),
 transport=require(path.join(q.source,'tools/lib/verification-darwin-session')),
 scopeAPI=require(path.join(q.source,'tools/lib/macos-command-scope')),
 {createStorageChild}=require(path.join(q.source,'tools/lib/verification-darwin-storage-guardian'));
const births={},children=[];let session;
function bounded(promise,ms=25000){let timer;return Promise.race([promise,new Promise((resolve,reject)=>{timer=setTimeout(()=>reject(Object.assign(new Error(),{code:'qa_writer_timeout'})),ms);})]).finally(()=>clearTimeout(timer));}
function child(role){
 const processChild=createStorageChild({config:session.config,source_sha256:session.capability.source_sha256,
  deadline_ns:String(process.hrtime.bigint()+120000000000n),cleanup_ms:30000,macosWorkerRoot:q.source,
  ...(role==='writer'?{macosWritableRoot:q.project}:{}),beforeMacOSPermit:async value=>{
   births[role]=value;return role==='writer'?session.registerStateWriter(value):session.registerAuthorityCustody(value);
  }});
 const queue=[],waiters=[];let failure;
 processChild.on('message',value=>waiters.length?waiters.shift().resolve(value):queue.push(value));
 processChild.on('error',error=>{failure=error;while(waiters.length)waiters.shift().reject(error);});
 const exit=new Promise(resolve=>processChild.once('exit',(code,signal)=>resolve({code,signal,...processChild.storageSnapshot()})));
 const next=()=>failure?Promise.reject(failure):queue.length?Promise.resolve(queue.shift()):new Promise((resolve,reject)=>waiters.push({resolve,reject}));
 const send=value=>bounded(new Promise((resolve,reject)=>processChild.send(value,error=>error?reject(error):resolve())));
 const result={process:processChild,exit,next,send};children.push(result);return result;
}
(async()=>{
 const configured=sessions.configuration({macosWorkspace:{workspace_id:q.workspace_id,broker_path:q.binary,broker_socket:q.socket}});
 session=await bounded(sessions.openSession({...configured,deadlineNs:process.hrtime.bigint()+150000000000n,cleanupMs:30000}));
 await bounded(session.expectAuthority());const authority=child('authority');
 await authority.send({type:'start',role:'authority',input:session.authorityInput()});
 const registered=await bounded(authority.next());assert.equal(registered.type,'registered');assert.equal(registered.reply.ok,true);
 const writer=child('writer');await bounded(writer.process.nativeReady);await bounded(session.permit());
 const owner_exec_source="const cp=require('node:child_process');const r=cp.spawnSync("+JSON.stringify(q.canary)+",[],{encoding:'utf8'});console.log(JSON.stringify({uid:process.getuid(),denied:!!r.error&&['EPERM','EACCES'].includes(r.error.code),errno:r.error?.code||null,status:r.status,stdout:r.stdout||''}));";
 let owner_exec_output='';const owner_exec_command=await bounded(session.run({executable:process.execPath,args:['-e',owner_exec_source],cwd:q.project,env:{}},{onStdout:bytes=>{owner_exec_output+=bytes;}}));
 assert.equal(owner_exec_command.status,0);assert.equal(owner_exec_command.cleanup.status,'completed');
 const owner_exec=JSON.parse(owner_exec_output);assert.notEqual(owner_exec.uid,process.getuid());assert.equal(owner_exec.denied,true);assert.equal(owner_exec.stdout,'');
 await writer.send({type:'start',role:'probe',root:q.project});const checked=await bounded(writer.next());
 assert.equal(checked.type,'checked');assert.equal(checked.uid,process.getuid());assert.equal(checked.pid,births.writer.writer.pid);
 const race=path.join(q.project,'race'),saved=path.join(q.project,'race-before-substitution');
 const before=fs.lstatSync(race,{bigint:true});assert(before.isDirectory()&&!before.isSymbolicLink());
 assert.equal(String(before.dev),checked.checked_directory.dev);assert.equal(String(before.ino),checked.checked_directory.ino);
 fs.renameSync(race,saved);const renamed=fs.lstatSync(saved,{bigint:true});assert.equal(renamed.ino,before.ino);assert.equal(renamed.dev,before.dev);
 fs.symlinkSync(q.outside,race,'dir');const replacement=fs.lstatSync(race,{bigint:true});assert(replacement.isSymbolicLink());
 assert.equal(fs.realpathSync(race),q.outside);await writer.send({type:'continue'});const probe=await bounded(writer.next());
 assert.equal(probe.type,'probe');assert.equal(probe.uid,process.getuid());assert.equal(probe.pid,births.writer.writer.pid);
 assert.equal(probe.inside_control,true);assert(['EACCES','EPERM'].includes(probe.outside_errno));
 assert.equal(fs.readFileSync(path.join(q.outside,'canary'),'utf8'),'unchanged');
 const drain=await bounded(session.drain()),closed=await bounded(session.close());assert.equal(drain.status,'completed');assert.equal(closed.status,'completed');
 await writer.send({type:'finish'});assert.equal((await bounded(writer.next())).type,'finished');
 const writer_exit=await bounded(writer.exit),authority_exit=await bounded(authority.exit);
 assert.equal(writer_exit.writer_exit_observed,true);assert.equal(writer_exit.code,0);assert.equal(writer_exit.signal,null);
 assert.equal(writer_exit.writer_sandbox,'workspace.v1');assert.equal(writer_exit.writable_root_sha256,crypto.createHash('sha256').update(q.project).digest('hex'));
 assert.equal(authority_exit.writer_exit_observed,true);assert.equal(authority_exit.signal,'SIGKILL');
 const observation_nonce=crypto.randomBytes(32).toString('hex');
 const native_closure=(await bounded(transport.rpc(session.config,{op:'observe_scope',attempt_id:session.binding.attempt_id,
  descriptor_sha256:session.binding.descriptor_sha256,observation_nonce},{limitMs:20000}))).reply;
 assert.equal(scopeAPI.validateObservation(native_closure,session.scope,session.capability,observation_nonce).status,'completed');
 console.log(JSON.stringify({ok:true,attempt_id:session.binding.attempt_id,scope:session.scope,capability:session.capability,
  births,native_closure,observation_nonce,writer_exit,authority_exit,checked_directory:checked.checked_directory,
  renamed_directory:{dev:String(renamed.dev),ino:String(renamed.ino)},
  substituted_symlink:{dev:String(replacement.dev),ino:String(replacement.ino),target:fs.readlinkSync(race)},
  probe,owner_exec,owner_exec_command,outside_unchanged:true,automatic_native_cleanup:true,external_recovery_requested:false}));
})().catch(async error=>{
 const end=process.hrtime.bigint()+30000000000n;
 if(session)await bounded(session.stop('qa_writer_failed'),30000).catch(()=>{});
 for(const value of children)value.process.stopWithin(end);
 await bounded(Promise.all(children.map(value=>value.exit)),30000).catch(()=>{});
 console.log(JSON.stringify({ok:false,code:/^[A-Za-z0-9_]{1,100}$/.test(error.code||'')?error.code:'qa_writer_failed'}));process.exitCode=2;
});
"""


def run_cases(runner, base, info, directory):
    started = time.monotonic();row = {'name': CASE, 'status': 'FAIL', 'observations': {}}
    runner.case_results.append(row);runner.public_started = True;runner.public_completed = False
    helper = runner.evidence/'macos-writer-provision'
    built = runner.run('compile-writer-workspace-provision', ['/usr/bin/cc','-std=c11','-D_DARWIN_C_SOURCE','-Wall','-Wextra',
        str(directory/'macos-workspace-provision.c'),'-o',str(helper)], timeout=60)
    runner.check(built.returncode == 0, 'macos_writer_provision_compile_failed')
    project = runner.fixture/'writer-project';outside = runner.fixture/'writer-outside';source = runner.fixture/'writer-package'
    created = runner.root('provision-writer-project', '/usr/bin/env','GITHUB_ACTIONS=true',str(helper),str(project),str(os.getuid()),'2000000001',timeout=30)
    capability = json.loads(created.stdout);runner.check(capability.pop('ok',False) is True,'macos_writer_provision_failed');capability.pop('owner_uuid',None)
    runner.root('create-writer-outside-control',sys.executable,'-c',
        'import os,sys;p=sys.argv[1];os.mkdir(p,0o700);os.chown(p,int(sys.argv[2]),-1);f=os.open(p+"/canary",os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600);os.write(f,b"unchanged");os.fchown(f,int(sys.argv[2]),-1);os.close(f)',str(outside),str(os.getuid()))
    # The original owner really can write this outside inode. Permission denial
    # in the probe must therefore come from the native writer profile.
    outside_file = outside/'canary';outside_file.write_bytes(b'owner-control');outside_file.write_bytes(b'unchanged')
    (project/'race').mkdir(mode=0o700)
    canary_binary=runner.evidence/'macos-owner-exec-canary';canary=project/'qa-owner-exec-canary'
    compiled=runner.run('compile-owner-exec-canary',['/usr/bin/cc','-std=c11','-Wall','-Wextra','-Werror',str(directory/'macos-owner-exec-canary.c'),'-o',str(canary_binary)],timeout=60)
    runner.check(compiled.returncode==0,'macos_owner_exec_compile_failed')
    runner.root('install-owner-setuid-canary','/usr/bin/install','-o',str(os.getuid()),'-g','2000000001','-m','4755',str(canary_binary),str(canary))
    installed=canary.stat();runner.check(installed.st_uid==os.getuid() and installed.st_uid!=0 and installed.st_mode&0o7777==0o4755,'macos_owner_exec_install_failed')
    control=runner.run('original-owner-exec-positive-control',[str(canary)],timeout=10);owner_control=json.loads(control.stdout)
    runner.check(control.returncode==0 and owner_control.get('ruid')==os.getuid() and owner_control.get('euid')==os.getuid(),'macos_owner_exec_control_failed')
    stage = runner.evidence/'macos-writer-package-stage';shutil.copytree(runner.runtime_copy,stage)
    (stage/'tools/lib/macos-command-worker.js').write_text(WORKER)
    script = ('import os,shutil,sys,stat;src,dst=sys.argv[1:];assert not os.path.lexists(dst);shutil.copytree(src,dst);'
        '\nfor root,dirs,files in os.walk(dst):\n os.chown(root,0,0);os.chmod(root,0o555)\n'
        ' for name in files:\n  p=os.path.join(root,name);s=os.lstat(p);assert stat.S_ISREG(s.st_mode) and s.st_nlink==1;os.chown(p,0,0);os.chmod(p,0o444)\n')
    runner.root('install-immutable-writer-probe-package',sys.executable,'-c',script,str(stage),str(source),timeout=90)
    capability.update(protected_worker_root=str(source),executables={str(info['node']):base.sha_file(info['node'])})
    runner.check(len(capability)==10,'macos_writer_capability_shape');workspace_id=base.sha_bytes(base.canonical(capability))
    registration=runner.evidence/'macos-writer-workspaces.private.json'
    base.private_file(registration,base.canonical({'schema':'knowledge-macos-workspaces.v1','workspaces':{workspace_id:capability}}))
    target=runner.roots['registry']/'macos-workspaces.json'
    runner.root('require-absent-writer-registration',sys.executable,'-c','import os,sys;assert not os.path.lexists(sys.argv[1])',str(target))
    runner.root('install-writer-registration','/usr/bin/install','-o','0','-g','0','-m','0600',str(registration),str(target))
    caller=runner.evidence/'macos-writer-sandbox-caller.cjs';base.private_file(caller,CALLER.encode())
    members=[{'path':item.relative_to(stage).as_posix(),'bytes':item.stat().st_size,'sha256':base.sha_file(item)} for item in sorted(stage.rglob('*')) if item.is_file()]
    base.private_file(runner.evidence/'MACOS_WRITER_SANDBOX_INPUTS.json',base.canonical({
        'worker_sha256':base.sha_bytes(WORKER.encode()),'caller_sha256':base.sha_bytes(CALLER.encode()),
        'owner_canary_source_sha256':base.sha_file(directory/'macos-owner-exec-canary.c'),'owner_canary_binary_sha256':base.sha_file(canary_binary),
        'owner_control':owner_control,'owner_canary_installed_mode':installed.st_mode&0o7777,'owner_canary_installed_uid':installed.st_uid,
        'provision_source_sha256':base.sha_file(directory/'macos-workspace-provision.c'),'provision_binary_sha256':base.sha_file(helper),
        'protected_package_members':members,'protected_package_sha256':base.sha_bytes(base.canonical(members)),'package_derivation':DERIVATION}))
    request={'source':str(source),'project':str(project),'outside':str(outside),'canary':str(canary),'workspace_id':workspace_id,
        'binary':str(info['binary']),'socket':str(info['socket'])}
    result=runner.run('native-original-uid-writer-sandbox',[str(info['node']),str(caller)],data=base.canonical(request),timeout=210)
    proof=None
    for line in result.stdout.splitlines():
        value=json.loads(line);runner.check(proof is None,'macos_writer_multiple_results');proof=value
    row.update(controller_exit_code=result.returncode,terminal=proof)
    runner.check(result.returncode==0 and proof and proof.get('ok') is True,'macos_writer_probe_failed')
    runner.check(proof.get('outside_unchanged') is True and outside_file.read_bytes()==b'unchanged','macos_writer_outside_changed')
    runner.check(proof['checked_directory']==proof['renamed_directory'] and proof['substituted_symlink']['target']==str(outside),
        'macos_writer_substitution_not_realized')
    entries=(runner.fixture_registry_snapshot() or {}).get('attempts',{})
    runner.check(len(entries)==1 and proof['attempt_id'] in entries,'macos_writer_attempt_unbound')
    entry=entries[proof['attempt_id']];uid=entry['descriptor']['task_ruid']
    runner.task_uids.add(uid);runner.expected_allocation_ids.add(proof['attempt_id'])
    runner.check(entry['descriptor_sha256']==proof['scope']['binding']['descriptor_sha256'],'macos_writer_descriptor_unbound')
    runner.check(proof['owner_exec'].get('uid')==uid and proof['owner_exec'].get('denied') is True and proof['owner_exec'].get('stdout')=='','macos_owner_exec_denial_unconfirmed')
    probe=proof['probe'];runner.check(probe.get('uid')==os.getuid() and probe.get('uid')!=uid and
        probe.get('pid')==entry['state_writer']['pid'] and probe.get('inside_control') is True and
        probe.get('outside_errno') in ('EPERM','EACCES'),'macos_writer_identity_or_denial_unconfirmed')
    proof['registered_actors']={role:entry[role] for role in ('authority','authority_guardian','state_writer','state_guardian','controller')}
    proof['actor_observations']={}
    for role in ('authority','authority_guardian','state_writer','state_guardian','controller'):
        runner.check(entry.get(role),'macos_writer_actor_missing')
        proof['actor_observations'][role]=runner.compare_birth(entry[role])
        runner.check(proof['actor_observations'][role].get('state') in ('absent','replaced'),'macos_writer_actor_still_present')
    observed=runner.root('macos-writer-independent-uid-zero',str(runner.uid_scan),str(uid),timeout=15)
    scanned=json.loads(observed.stdout);runner.check(scanned.get('observation_valid') is True and scanned.get('member_count')==0,'macos_writer_uid_active')
    proof['independent_uid_scan']=scanned
    base.private_file(runner.evidence/'MACOS_WRITER_SANDBOX_PROOF.private.json',base.canonical(proof))
    row['proof_sha256']=base.sha_bytes(base.canonical(proof));row['observations'].update(
        original_uid_writer=True,original_owner_setuid_positive_control=True,private_uid_setuid_exec_denied=True,inside_control_write_succeeded=True,owner_outside_write_control_succeeded=True,
        actual_checked_directory_replaced=True,outside_write_denied_by_native_profile=True,outside_unchanged=True,
        exact_actor_exits=True,independent_uid_zero=True,automatic_native_cleanup=True,external_recovery_requested=False,
        private_allocation_count=1,qa_derived_native_boundary_only=True,shipping_flow_proof=False)
    row.update(status=STATUS,elapsed_ms=(time.monotonic()-started)*1000);runner.public_completed=True


def main():
    path=Path(__file__).with_name('darwin-production-lifecycle.py')
    spec=importlib.util.spec_from_file_location('macos_writer_fixture_base',path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    if '--case-set' not in sys.argv:sys.argv.extend(['--case-set','writable-sandbox'])
    return module.main()


if __name__=='__main__':raise SystemExit(main())
