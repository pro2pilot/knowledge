#!/usr/bin/env python3
"""Disposable hosted-macOS public Flow/evaluation writable-scope qualification.

Uses the existing exact-inode installation/cleanup owner. No shipping source
is modified: the fixed QA leaf is added to a separately pinned immutable copy.
Raw descriptors, paths and process identities stay in private evidence.
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

CASES = ('normal_two_flow_steps', 'evaluation_check', 'cancel', 'controller_death',
         'double_guardian_controller_death', 'state_writer_fifo_read_cancel')
ACTORS = ('authority', 'authority_guardian', 'state_writer', 'state_guardian', 'controller')

LEAF = r"""'use strict';
const fs=require('node:fs'),path=require('node:path'),assert=require('node:assert/strict'),cp=require('node:child_process');
const root=process.cwd(),mode=process.argv[2],file=name=>path.join(root,name);
const write=(name,value)=>fs.writeFileSync(file(name),JSON.stringify(value),{mode:0o600});
if(mode==='grandchild'){write('qa-grandchild.json',{pid:process.pid,uid:process.getuid()});setInterval(()=>fs.appendFileSync(file('qa-heartbeat'),'x'),20);}
else if(mode==='child'){cp.spawn(process.execPath,[__filename,'grandchild'],{cwd:root,detached:true,stdio:'ignore'}).unref();write('qa-child.json',{pid:process.pid,uid:process.getuid()});setInterval(()=>{},1000);}
else if(mode==='first'||mode==='hold'){
 process.umask(0o077);write('qa-first.json',{uid:process.getuid(),pid:process.pid});
 fs.writeFileSync(file('qa-private0600'),'original',{mode:0o600});
 const scratch=path.join(process.env.TMPDIR,'qa-scratch0600');fs.writeFileSync(scratch,'scratch',{mode:0o600});
 fs.renameSync(scratch,file('qa-renamed0600'));
 let outside=false,metadata=false,identity=false;
 try{fs.writeFileSync(process.env.KNOWLEDGE_QA_OUTSIDE,'escaped');}catch(error){outside=['EACCES','EPERM'].includes(error.code);}
 try{fs.chmodSync(file('qa-private0600'),0o777);}catch(error){metadata=['EACCES','EPERM'].includes(error.code);}
 try{process.setuid(Number(process.env.KNOWLEDGE_QA_OWNER));}catch(error){identity=['EACCES','EPERM'].includes(error.code);}
 const external=cp.spawnSync('/usr/bin/true',[],{stdio:'ignore'});
 assert(outside&&metadata&&identity&&(external.error||external.status!==0));
 cp.spawn(process.execPath,[__filename,'child'],{cwd:root,detached:true,stdio:'ignore'}).unref();
 const end=Date.now()+10000;const timer=setInterval(()=>{
  if(fs.existsSync(file('qa-grandchild.json'))){clearInterval(timer);write('qa-ready.json',{uid:process.getuid(),pid:process.pid});
   if(mode==='first')console.log(JSON.stringify({status:'ok',uid:process.getuid(),detached_tree_ready:true,
    private_uid_outside_write_denied:outside,metadata_change_denied:metadata,owner_uid_escalation_denied:identity,nonpinned_exec_denied:true}));else setInterval(()=>{},1000);
  }else if(Date.now()>end){clearInterval(timer);process.exitCode=3;}
 },20);
}else if(mode==='second'){
 const first=JSON.parse(fs.readFileSync(file('qa-first.json'),'utf8'));assert.notEqual(first.uid,process.getuid());
 for(const name of ['qa-private0600','qa-renamed0600']){assert(fs.readFileSync(file(name),'utf8').length);fs.appendFileSync(file(name),'next');}
 console.log(JSON.stringify({status:'ok',uid:process.getuid(),previous_uid:first.uid,writable_continuity:true}));
}else throw new Error('qa_case_invalid');
"""

CALLER = r"""'use strict';
const fs=require('node:fs'),path=require('node:path'),assert=require('node:assert/strict');
const q=JSON.parse(fs.readFileSync(0,'utf8')),abort=new AbortController();
process.on('SIGTERM',()=>abort.abort());
Object.assign(process.env,{KNOWLEDGE_MACOS_WORKSPACE_ID:q.workspace_id,KNOWLEDGE_MACOS_BROKER_PATH:q.binary,
 KNOWLEDGE_MACOS_BROKER_SOCKET:q.socket,KNOWLEDGE_SYSTEM_ROOT:q.source,KNOWLEDGE_TARGET_ROOT:q.project,
 KNOWLEDGE_PROJECT_KNOWLEDGE_ROOT:path.join(q.project,'.knowledge'),KNOWLEDGE_STATE_ROOT:path.join(q.project,'.knowledge'),
 KNOWLEDGE_QA_OUTSIDE:q.outside,KNOWLEDGE_QA_OWNER:String(q.owner_uid),
 KNOWLEDGE_DISABLE_GIT_DISCOVERY:'1',KNOWLEDGE_FLOW_NO_OPEN:'1',CI:'true'});
const context={mode:'repo',systemRoot:q.source,targetRoot:q.project,projectKnowledgeRoot:path.join(q.project,'.knowledge'),
 stateRoot:path.join(q.project,'.knowledge'),teamRoot:null,repoId:'macos-physical-fixture',workspaceId:null,agentId:'macos-ci',
 branch:null,headSha:null,isGitWorktree:false,git:{},warnings:[]};
const options={signal:abort.signal,budgets:{setupMs:30000,workMs:60000,cleanupMs:30000,progressMs:0},
 macosWorkspace:{workspace_id:q.workspace_id,broker_path:q.binary,broker_socket:q.socket}};
(async()=>{
 const flow=require(path.join(q.source,'tools/flow.js'));let value;
 if(q.case==='normal_two_flow_steps'){
  const first=await flow.runOneAsync('macos-qa-step.js first',context,options);
  assert.equal(first.success,true);assert.equal(first.ownership.status,'completed');
  for(const name of ['qa-private0600','qa-renamed0600']){assert(fs.readFileSync(path.join(q.project,name),'utf8').length);fs.appendFileSync(path.join(q.project,name),'owner');}
  const second=await flow.runOneAsync('macos-qa-step.js second',context,options);
  assert.equal(second.success,true);assert.equal(second.ownership.status,'completed');
  assert.notEqual(first.parsed.uid,second.parsed.uid);value={first,second,owner_write_continuity:true};
 }else if(q.case==='evaluation_check'){
  value=await require(path.join(q.source,'tools/evaluation-harness.js')).runCheckAsync({name:'writable-continuity',command:'tools/macos-qa-step.js second'},options);
  assert.equal(value.status,'pass');assert.equal(value.ownership.status,'completed');
 }else if(q.case==='state_writer_fifo_read_cancel') value=await flow.runFlowAsync({name:'lint',context},options);
 else value=await flow.runOneAsync('macos-qa-step.js hold',context,options);
 console.log(JSON.stringify({type:'result',ok:true,value}));
})().catch(error=>{console.log(JSON.stringify({type:'result',ok:false,code:error.code||'untyped',cleanup:error.cleanup||null,
 recovery_required:error.recovery_required===true}));process.exitCode=2;});
"""


def install(runner, base, info, directory):
    helper = runner.evidence/'macos-workspace-provision'
    built = runner.run('compile-macos-workspace-provision', ['/usr/bin/cc', '-std=c11', '-D_DARWIN_C_SOURCE',
        '-Wall', '-Wextra', str(directory/'macos-workspace-provision.c'), '-o', str(helper)], timeout=60)
    runner.check(built.returncode == 0, 'macos_workspace_provision_compile_failed')
    project = runner.fixture/'macos-project'
    outside = runner.fixture/'macos-outside-canary'
    runner.root('create-owner-writable-outside-canary', sys.executable, '-c',
        'import os,sys;p=sys.argv[1];assert not os.path.lexists(p);f=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600);os.write(f,b"unchanged");os.fchown(f,int(sys.argv[2]),-1);os.close(f)',
        str(outside), str(os.getuid()))
    created = runner.root('provision-owned-writable-workspace', '/usr/bin/env', 'GITHUB_ACTIONS=true', str(helper),
        str(project), str(os.getuid()), '2000000001', timeout=30)
    capability = json.loads(created.stdout)
    runner.check(capability.pop('ok', False) is True, 'macos_workspace_provision_failed')
    capability.pop('owner_uuid', None)
    stage = runner.evidence/'macos-package-stage'
    import shutil
    shutil.copytree(runner.runtime_copy, stage)
    (stage/'tools/macos-qa-step.js').write_text(LEAF)
    source = runner.fixture/'macos-package'
    script = ('import os,shutil,sys,stat;src,dst=sys.argv[1:];assert not os.path.lexists(dst);shutil.copytree(src,dst);'
        '\nfor root,dirs,files in os.walk(dst):\n os.chown(root,0,0);os.chmod(root,0o555)\n'
        ' for name in files:\n  p=os.path.join(root,name);s=os.lstat(p);assert stat.S_ISREG(s.st_mode) and s.st_nlink==1;os.chown(p,0,0);os.chmod(p,0o444)\n')
    runner.root('install-immutable-macos-package', sys.executable, '-c', script, str(stage), str(source), timeout=90)
    shutil.copytree(runner.runtime_copy, project/'.knowledge')
    capability.update(protected_worker_root=str(source), executables={str(info['node']): base.sha_file(info['node'])})
    runner.check(len(capability) == 10, 'macos_workspace_capability_shape')
    workspace_id = hashlib.sha256(base.canonical(capability)).hexdigest()
    registration = runner.evidence/'macos-workspaces.private.json'
    base.private_file(registration, base.canonical({'schema': 'knowledge-macos-workspaces.v1', 'workspaces': {workspace_id: capability}}))
    target = runner.roots['registry']/'macos-workspaces.json'
    runner.root('require-absent-macos-registration', sys.executable, '-c', 'import os,sys;assert not os.path.lexists(sys.argv[1])', str(target))
    runner.root('install-owned-macos-registration', '/usr/bin/install', '-o', '0', '-g', '0', '-m', '0600', str(registration), str(target))
    caller = runner.evidence/'macos-writable-caller.cjs';base.private_file(caller, CALLER.encode())
    package_rows = [{'path': item.relative_to(stage).as_posix(), 'bytes': item.stat().st_size,
        'sha256': base.sha_file(item)} for item in sorted(stage.rglob('*')) if item.is_file()]
    base.private_file(runner.evidence/'MACOS_WRITABLE_INPUTS.json', base.canonical({
        'leaf_sha256': base.sha_bytes(LEAF.encode()), 'caller_sha256': base.sha_bytes(CALLER.encode()),
        'provision_source_sha256': base.sha_file(directory/'macos-workspace-provision.c'),
        'provision_binary_sha256': base.sha_file(helper), 'protected_package_sha256': base.sha_bytes(base.canonical(package_rows)),
        'protected_package_members': package_rows,
        'package_derivation': 'exact runtime copy plus fixed QA leaf and compiled source-bound addon'}))
    return {'source': source, 'project': project, 'workspace_id': workspace_id, 'caller': caller, 'outside': outside}


def run_cases(runner, base, info, directory):
    fixture = install(runner, base, info, directory)
    spec = importlib.util.spec_from_file_location('macos_writable_failure_helpers', directory/'darwin-production-failure-cases.py')
    failures = importlib.util.module_from_spec(spec);spec.loader.exec_module(failures)
    helpers = failures.compile_helpers(runner, base, directory);runner.failure_helpers = helpers
    batch_source = runner.evidence/'macos-exact-signal-batch.c'
    batch_code = ('#define main single_signal_main\n#include "darwin-test-signal.c"\n#undef main\n'
        'int main(int argc,char **argv){if(argc!=22)return 64;for(int i=1;i<argc;i+=7){'
        'char *one[8]={argv[0]};for(int j=0;j<7;j++)one[j+1]=argv[i+j];'
        'int result=single_signal_main(8,one);if(result)return result;}return 0;}\n')
    base.private_file(batch_source, batch_code.encode());batch_binary = runner.evidence/'macos-exact-signal-batch'
    compiled = runner.run('compile-macos-exact-signal-batch', ['/usr/bin/cc', '-std=c11', '-D_DARWIN_C_SOURCE',
        '-Wall', '-Wextra', '-Werror', '-I', str(directory), str(batch_source), '-o', str(batch_binary)], timeout=60)
    runner.check(compiled.returncode == 0, 'macos_writable_batch_signal_compile_failed')
    base.private_file(runner.evidence/'MACOS_SIGNAL_BATCH_INPUTS.json', base.canonical({
        'source_sha256':base.sha_file(batch_source),'binary_sha256':base.sha_file(batch_binary),
        'included_exact_signal_source_sha256':base.sha_file(directory/'darwin-test-signal.c')}))

    def parse(result):
        runner.check(result.returncode == 0, 'macos_writable_observer_failed')
        return json.loads(result.stdout)

    def birth(pid):
        value = parse(runner.sudo(str(helpers['process_observer']), str(pid), name='macos-writable-observe-birth', timeout=10))
        runner.check(value.get('pid') == pid and value.get('ruid') == os.getuid() and
            value.get('image') in (str(info['node']), str(info['binary'])), 'macos_writable_actor_identity')
        return value

    def send(identity, sig):
        result = runner.root('macos-writable-signal-exact-birth', str(helpers['signal']), str(identity['pid']),
            str(identity['unique_id']), str(identity['start_sec']), str(identity['start_usec']),
            str(os.getuid()), str(sig), identity['image'], timeout=10)
        value = parse(result)
        runner.check(value.get('exact_birth_checked') is True and value.get('native_result') == 0,
            'macos_writable_signal_unconfirmed')

    def entries():
        return (runner.fixture_registry_snapshot() or {}).get('attempts', {})

    def kill_three_exact(identities):
        argv = [str(batch_binary)]
        for identity in identities:
            argv.extend(str(value) for value in (identity['pid'],identity['unique_id'],identity['start_sec'],
                identity['start_usec'],os.getuid(),signal.SIGKILL,identity['image']))
        result = runner.root('macos-writable-three-exact-faults', *argv, timeout=15)
        replies = [json.loads(line) for line in result.stdout.splitlines()]
        runner.check(result.returncode == 0 and len(replies) == 3 and all(value.get('exact_birth_checked') is True
            and value.get('native_result') == 0 and value.get('signal') == signal.SIGKILL for value in replies),
            'macos_writable_three_faults_not_realized')

    for name in CASES:
        start = time.monotonic();deadline = start+210;before = set(entries());actors = {};process = None;fifo_fd = None
        row = {'name': name, 'status': 'FAIL', 'observations': {}};runner.case_results.append(row)
        runner.public_started = True;runner.public_completed = False
        project = fixture['project']
        for marker in ('qa-ready.json', 'qa-child.json', 'qa-grandchild.json'):
            candidate = project/marker
            if candidate.exists(): candidate.unlink()
        config_file = project/'.knowledge/config.yaml';saved_config = project/'.knowledge/config.before-fifo'
        if name == 'state_writer_fifo_read_cancel':
            runner.check(not saved_config.exists(), 'macos_writable_fifo_backup_exists')
            config_file.rename(saved_config);os.mkfifo(config_file, 0o600);fifo_fd = os.open(config_file, os.O_RDWR|os.O_NONBLOCK)
        request = {key: str(fixture[key]) for key in ('source', 'project', 'workspace_id')}
        request.update(case=name, binary=str(info['binary']), socket=str(info['socket']),
            outside=str(fixture['outside']), owner_uid=os.getuid())
        stdout = runner.evidence/(name+'.writable.stdout.raw');stderr = runner.evidence/(name+'.writable.stderr.raw')
        try:
            with stdout.open('wb') as out, stderr.open('wb') as err:
                process = subprocess.Popen([str(info['node']), str(fixture['caller'])], stdin=subprocess.PIPE, stdout=out, stderr=err)
                runner.active_monitor = process;process.stdin.write(base.canonical(request));process.stdin.close()
                actors['controller'] = birth(process.pid)
                if name not in ('normal_two_flow_steps', 'evaluation_check'):
                    entry = None
                    while time.monotonic() < deadline and process.poll() is None:
                        candidates = [(key, value) for key, value in entries().items() if key not in before]
                        if candidates:
                            attempt, entry = candidates[-1]
                            if all(entry.get(role) for role in ACTORS) and (name == 'state_writer_fifo_read_cancel' or (project/'qa-ready.json').exists()): break
                        time.sleep(.1)
                    runner.check(entry and all(entry.get(role) for role in ACTORS), 'macos_writable_execution_not_observed')
                    for role in ACTORS:
                        actors[role] = birth(entry[role]['pid'])
                        runner.check(all(str(actors[role][key]) == str(entry[role][key]) for key in ('pid','unique_id','start_sec','start_usec')),
                            'macos_writable_native_actor_mismatch')
                    base.private_file(runner.evidence/(name+'.actors.private.json'), base.canonical(actors))
                    if name == 'double_guardian_controller_death':
                        send(actors['state_writer'], signal.SIGSTOP);row['observations']['scheduling_pause_not_kernel_io'] = True
                        kill_three_exact([actors[role] for role in ('state_guardian', 'authority_guardian', 'controller')])
                        row['observations']['both_guardians_and_controller_exact_kill_delivered'] = True
                    elif name == 'controller_death': send(actors['controller'], signal.SIGKILL)
                    else:
                        if name == 'state_writer_fifo_read_cancel':
                            reader_deadline = min(deadline, time.monotonic()+20)
                            while time.monotonic() < reader_deadline:
                                observed = runner.sudo('/usr/sbin/lsof', '-a', '-p', str(actors['state_writer']['pid']), str(config_file),
                                    name='macos-writable-actual-fifo-reader', timeout=10)
                                if observed.returncode == 0 and str(config_file).encode() in observed.stdout: break
                                runner.check(process.poll() is None, 'macos_writable_fifo_controller_exited');time.sleep(.1)
                            runner.check(observed.returncode == 0 and str(config_file).encode() in observed.stdout,
                                'macos_writable_fifo_read_not_observed')
                            row['observations']['actual_state_writer_fifo_fd_observed'] = True
                        send(actors['controller'], signal.SIGTERM)
                process.wait(timeout=max(1, deadline-time.monotonic()))
            terminal = None
            for line in stdout.read_bytes().splitlines():
                value = json.loads(line)
                if value.get('type') == 'result': runner.check(terminal is None, 'macos_writable_duplicate_terminal');terminal = value
            row.update(controller_exit_code=process.returncode, terminal=terminal)
            if name in ('normal_two_flow_steps', 'evaluation_check'):
                runner.check(process.returncode == 0 and terminal and terminal.get('ok') is True, 'macos_writable_public_operation_failed')
            elif name in ('cancel', 'state_writer_fifo_read_cancel'):
                runner.check(process.returncode == 2 and terminal and terminal.get('ok') is False and terminal.get('code') == 'command_cancelled'
                    and (terminal.get('cleanup') or {}).get('status') == 'completed' and terminal.get('recovery_required') is False,
                    'macos_writable_cancel_not_reported')
            else: runner.check(process.returncode == -signal.SIGKILL and terminal is None, 'macos_writable_controller_death_not_observed')
            after = entries();created = {key: value for key, value in after.items() if key not in before}
            runner.check(len(created) == (2 if name == 'normal_two_flow_steps' else 1), 'macos_writable_allocation_count')
            for attempt, entry in created.items():
                runner.task_uids.add(entry['descriptor']['task_ruid']);runner.expected_allocation_ids.add(attempt)
                closure_deadline = min(deadline, time.monotonic()+35)
                while time.monotonic() < closure_deadline:
                    nonce = os.urandom(32).hex()
                    observation = runner.native_request(info, {'op':'observe_scope','attempt_id':attempt,'descriptor_sha256':entry['descriptor_sha256'],
                        'observation_nonce':nonce}, 'macos-writable-observe-scope', timeout=10)
                    if observation.get('status') == 'completed': break
                    time.sleep(.1)
                runner.check(observation.get('status') == 'completed' and observation.get('observation_nonce') == nonce and
                    observation.get('descriptor_sha256') == entry['descriptor_sha256'] and observation.get('attempt_id') == attempt and
                    observation.get('schema') == 'knowledge-darwin-scope-observation.v1' and
                    observation.get('source_sha256') == runner.binaries['shipping']['source_sha256'] and
                    observation.get('capability_qualified') is True and observation.get('observation_cached') is False and
                    observation.get('cleanup_only') is True and observation.get('proof_current') is False and
                    all(observation.get(key) is True for key in ('kernel_membership_zero','admission_closed','spawn_exclusion_acquired',
                    'spawn_intents_resolved','guardian_exit_confirmed','root_child_exit_confirmed','registered_authority_exited','native_scope_closed')),
                    'macos_writable_native_closure_unconfirmed')
                uid = parse(runner.sudo(str(runner.uid_scan), str(entry['descriptor']['task_ruid']), name='macos-writable-independent-uid-zero', timeout=15))
                runner.check(uid.get('observation_valid') is True and uid.get('member_count') == 0, 'macos_writable_uid_not_empty')
                for role in ACTORS:
                    if entry.get(role):
                        runner.check(runner.compare_birth(entry[role]).get('state') in ('absent','replaced'),
                            'macos_writable_registered_actor_still_present')
            for identity in actors.values():
                runner.check(runner.compare_birth(identity).get('state') in ('absent','replaced'), 'macos_writable_actor_still_present')
            runner.check(fixture['outside'].read_bytes() == b'unchanged', 'macos_writable_outside_canary_changed')
            row['observations'].update(exact_actor_exits=True, independent_uid_zero=True, typed_native_closure=True,
                private_allocation_count=len(created), acceptance_after_cancel=False,
                automatic_native_cleanup=True, external_recovery_requested=False, outside_canary_unchanged=True)
            row.update(status='PASS_PHYSICAL_MACOS_WRITABLE', elapsed_ms=(time.monotonic()-start)*1000)
            runner.public_completed = True
        finally:
            if fifo_fd is not None: os.close(fifo_fd)
            if name == 'state_writer_fifo_read_cancel' and runner.public_completed:
                config_file.unlink();saved_config.rename(config_file)
            if process is not None and process.poll() is not None: runner.active_monitor = None


def main():
    target = Path(__file__).with_name('darwin-production-lifecycle.py')
    spec = importlib.util.spec_from_file_location('macos_writable_installation_owner', target)
    module = importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    sys.argv.extend(['--case-set', 'writable'])
    return module.main()


if __name__ == '__main__':
    raise SystemExit(main())
