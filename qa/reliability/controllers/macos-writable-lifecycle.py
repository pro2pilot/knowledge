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
import stat
import subprocess
import sys
import time

CASES = ('normal_two_flow_steps', 'evaluation_check', 'cancel', 'controller_death',
         'double_guardian_controller_death', 'state_writer_fifo_read_cancel', 'team_flow_controller_death_retry')
ACTORS = ('authority', 'authority_guardian', 'state_writer', 'state_guardian', 'controller')

def observe_fifo_reader(runner, helpers, identity, target, name):
    result = runner.sudo(str(helpers['process_observer']), '--fifo',
        *(str(identity[key]) for key in ('pid', 'unique_id', 'start_sec', 'start_usec', 'ruid')), str(target),
        name=name, timeout=10)
    runner.check(result.returncode in (0, 1), 'macos_fifo_observer_failed')
    value = json.loads(result.stdout)
    flags = ('observed', 'target_fifo', 'birth_before', 'birth_after', 'target_stable', 'fd_scan_complete')
    counts = ('fd_count', 'vnode_count', 'fifo_count', 'exact_read_fd_count', 'errno')
    runner.check(isinstance(value, dict) and value.get('schema') == 'knowledge-macos-qa-fifo-reader.v1'
        and all(type(value.get(key)) is bool for key in flags)
        and all(type(value.get(key)) is int and 0 <= value[key] <= 16384 for key in counts)
        and (result.returncode == 0) is value['observed'], 'macos_fifo_observer_protocol')
    if value['observed']:
        runner.check(all(value[key] is True for key in flags) and value['exact_read_fd_count'] == 1 and value['errno'] == 0
            and value['fd_count'] >= value['vnode_count'] >= value['fifo_count'] >= 1,
            'macos_fifo_observer_identity_unconfirmed')
    return value


MAX_TEAM_DOCTOR_REPORT_BYTES = 2 * 1024 * 1024
TEAM_DOCTOR_REPORT_STATUSES = {'healthy', 'usable_with_warnings', 'structurally_broken'}


def bounded_stream_read(stream, maximum):
    if type(maximum) is not int or maximum < 0: raise ValueError('read_limit_invalid')
    body = stream.read(maximum + 1)
    if not isinstance(body, bytes) or len(body) > maximum: raise ValueError('read_limit_exceeded')
    return body


def no_symlink_components(root, path):
    root = Path(root).resolve(strict=True)
    candidate = Path(os.path.abspath(path))
    if not candidate.is_relative_to(root): return False
    current = root
    try:
        for part in candidate.relative_to(root).parts:
            current = current / part
            info = current.lstat()
            if stat.S_ISLNK(info.st_mode): return False
        return True
    except OSError:
        return False


def read_bounded_regular_file(path, maximum):
    """Read a stable unique regular file through a no-follow bounded fd."""
    path = Path(path)
    before = path.lstat()
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        raise ValueError('file_not_unique_regular')
    if before.st_size <= 0 or before.st_size > maximum:
        raise ValueError('file_size_out_of_bounds')
    flags = os.O_RDONLY | getattr(os, 'O_NONBLOCK', 0) | getattr(os, 'O_NOFOLLOW', 0)
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        identity = lambda item: (item.st_dev, item.st_ino, item.st_nlink, item.st_mode, item.st_size,
            item.st_mtime_ns)
        stable_descriptor = lambda item: (*identity(item), item.st_ctime_ns)
        if not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1 or identity(opened) != identity(before) or opened.st_size > maximum:
            raise ValueError('file_changed_before_read')
        with os.fdopen(descriptor, 'rb', closefd=False) as stream:
            body = bounded_stream_read(stream, maximum)
        after_fd = os.fstat(descriptor)
        after_path = path.lstat()
        if stat.S_ISLNK(after_path.st_mode) or not stat.S_ISREG(after_path.st_mode) or after_path.st_nlink != 1 or \
                stable_descriptor(after_fd) != stable_descriptor(opened) or identity(after_path) != identity(opened) or len(body) != opened.st_size:
            raise ValueError('file_changed_during_read')
        return body
    finally:
        os.close(descriptor)


def capture_team_doctor_report(runner, base, evidence, team_root, start, flow_value):
    """Retain a bounded private Doctor report and bind it conservatively to Flow.

    The timing and summary match is diagnostic evidence, not proof that this
    report was the exact parsed object consumed by Flow.
    """
    unavailable = {'status': 'unavailable', 'reason_code': 'report_missing',
        'bytes': None, 'sha256': None, 'binding': 'none', 'causal_proof': False}
    try:
        relative = Path(start.get('state_root', ''))
        if not relative.parts or relative.is_absolute() or any(part in ('', '.', '..') for part in relative.parts):
            unavailable['reason_code'] = 'state_root_invalid';return unavailable
        root = Path(team_root).resolve(strict=True)
        state_candidate = root / relative
        if not no_symlink_components(root, state_candidate):
            unavailable['reason_code'] = 'state_root_mismatch';return unavailable
        state = state_candidate.resolve(strict=True)
        if not state.is_relative_to(root) or Path(flow_value.get('state_root', '')).resolve(strict=True) != state:
            unavailable['reason_code'] = 'state_root_mismatch';return unavailable
        maintenance = state / 'maintenance'
        maintenance_stat = maintenance.lstat()
        if not stat.S_ISDIR(maintenance_stat.st_mode) or stat.S_ISLNK(maintenance_stat.st_mode):
            unavailable['reason_code'] = 'report_not_unique_regular';return unavailable
        report_path = maintenance / 'quality_report.json'
        if not report_path.resolve(strict=True).is_relative_to(state) or not no_symlink_components(state, report_path):
            unavailable['reason_code'] = 'report_not_unique_regular';return unavailable
        try: body = read_bounded_regular_file(report_path, MAX_TEAM_DOCTOR_REPORT_BYTES)
        except ValueError as error:
            unavailable['reason_code'] = 'report_size_out_of_bounds' if str(error) == 'file_size_out_of_bounds' else 'report_changed_during_read'
            return unavailable
        report = json.loads(body)
        if not isinstance(report, dict):
            unavailable['reason_code'] = 'report_shape_invalid';return unavailable
        score, status = report.get('quality_score'), report.get('status')
        generated = report.get('generated_at')
        started = flow_value.get('started_at');duration = flow_value.get('duration_total_ms')
        if not isinstance(generated, str) or not generated.endswith('Z') or not isinstance(started, str) or not started.endswith('Z'):
            unavailable['reason_code'] = 'report_flow_summary_mismatch';return unavailable
        timestamp = __import__('datetime').datetime.fromisoformat(generated.replace('Z', '+00:00')).timestamp()
        flow_begin = __import__('datetime').datetime.fromisoformat(started.replace('Z', '+00:00')).timestamp()
        if (report.get('mode') != 'team' or type(score) is not int or not 0 <= score <= 100 or
                status not in TEAM_DOCTOR_REPORT_STATUSES or not isinstance(generated, str) or
                not isinstance(started, str) or type(duration) is not int or not 0 <= duration <= 30 * 60 * 1000 or
                timestamp < flow_begin or timestamp > flow_begin + duration / 1000 + 5 or
                not isinstance(flow_value.get('steps'), list) or len(flow_value['steps']) != 8 or
                flow_value['steps'][-1].get('command') != 'doctor.js' or
                flow_value['steps'][-1].get('summary') != f'{score} /100 {status}'):
            unavailable['reason_code'] = 'report_flow_summary_mismatch';return unavailable
        destination = evidence / 'TEAM_DOCTOR_REPORT.private.json'
        base.private_file(destination, body)
        return {'status': 'captured', 'reason_code': None, 'bytes': len(body),
            'sha256': base.sha_bytes(body), 'binding': 'flow_time_window_and_step_summary_match',
            'generated_at': generated, 'causal_proof': False}
    except (OSError, ValueError, TypeError, KeyError, AttributeError):
        unavailable['reason_code'] = 'report_unreadable'
        return unavailable

LEAF = r"""'use strict';
const fs=require('node:fs'),path=require('node:path'),assert=require('node:assert/strict'),cp=require('node:child_process');
const root=process.cwd(),mode=process.argv[2],file=name=>path.join(root,name);
const write=(name,value)=>fs.writeFileSync(file(name),JSON.stringify(value),{mode:0o600});
let qaStage='leaf_bootstrap';
const stages=new Set(['leaf_bootstrap','first_write','scratch_write','scratch_rename','boundary_checks','child_spawn','child_write','grandchild_spawn','grandchild_write','grandchild_heartbeat','child_stderr','grandchild_stderr','child_exit','grandchild_exit','descendant_wait_timeout']);
const errno=new Set(['EPERM','EACCES','ENOENT','EINVAL','EAGAIN','ENOMEM','ENOSYS','EMFILE','ENFILE','ERR_ASSERTION']);
function record(stage,error,details={}){
 const value={qa_descendant_failure:true,stage:stages.has(stage)?stage:'leaf_bootstrap',code:errno.has(error?.code)?error.code:null,
  exit:Number.isInteger(details.exit)?details.exit:null,signal:['SIGKILL','SIGTERM','SIGABRT','SIGSEGV'].includes(details.signal)?details.signal:null};
 try{if(!fs.existsSync(file('qa-descendant-error.json')))write('qa-descendant-error.json',value);}catch{}
 try{fs.writeSync(2,JSON.stringify(value)+'\n');}catch{}
}
process.on('uncaughtException',error=>{record(qaStage,error);process.exit(5);});
function spawnDescendant(next){
 qaStage=next==='child'?'child_spawn':'grandchild_spawn';
 const child=cp.spawn(process.execPath,[__filename,next],{cwd:root,detached:true,stdio:['ignore','ignore','pipe']});
 child.on('error',error=>record(next==='child'?'child_spawn':'grandchild_spawn',error));
 let bytes='';child.stderr.on('data',part=>{bytes=(bytes+part.toString()).slice(0,4096);for(const line of bytes.split('\n')){try{const value=JSON.parse(line);if(value.qa_descendant_failure===true&&stages.has(value.stage))record(value.stage,{code:value.code},value);}catch{}}});
 child.stderr.on('error',error=>record(next==='child'?'child_stderr':'grandchild_stderr',error));
 child.once('exit',(exit,signal)=>{if(!fs.existsSync(file('qa-ready.json')))record(next==='child'?'child_exit':'grandchild_exit',null,{exit,signal});});
 child.stderr.unref();child.unref();return child;
}
if(mode==='grandchild'){qaStage='grandchild_write';write('qa-grandchild.json',{pid:process.pid,uid:process.getuid()});setInterval(()=>{qaStage='grandchild_heartbeat';fs.appendFileSync(file('qa-heartbeat'),'x');},20);}
else if(mode==='child'){spawnDescendant('grandchild');qaStage='child_write';write('qa-child.json',{pid:process.pid,uid:process.getuid()});setInterval(()=>{},1000);}
else if(mode==='first'||mode==='hold'){
 qaStage='first_write';process.umask(0o077);write('qa-first.json',{uid:process.getuid(),pid:process.pid});
 fs.writeFileSync(file('qa-private0600'),'original',{mode:0o600});
 qaStage='scratch_write';const scratch=path.join(process.env.TMPDIR,'qa-scratch0600');fs.writeFileSync(scratch,'scratch',{mode:0o600});
 qaStage='scratch_rename';fs.renameSync(scratch,file('qa-renamed0600'));qaStage='boundary_checks';
 let outside=false,metadata=false,identity=false;
 try{fs.writeFileSync(process.env.KNOWLEDGE_QA_OUTSIDE,'escaped');}catch(error){outside=['EACCES','EPERM'].includes(error.code);}
 try{fs.chmodSync(file('qa-private0600'),0o777);}catch(error){metadata=['EACCES','EPERM'].includes(error.code);}
 try{process.setuid(Number(process.env.KNOWLEDGE_QA_OWNER));}catch(error){identity=['EACCES','EPERM'].includes(error.code);}
 const external=cp.spawnSync('/usr/bin/true',[],{stdio:'ignore'});
 assert(outside&&metadata&&identity&&(external.error||external.status!==0));
 spawnDescendant('child');
 const end=Date.now()+10000;const timer=setInterval(()=>{
  if(fs.existsSync(file('qa-grandchild.json'))){clearInterval(timer);write('qa-ready.json',{uid:process.getuid(),pid:process.pid});
   if(mode==='first')console.log(JSON.stringify({status:'ok',uid:process.getuid(),detached_tree_ready:true,
    private_uid_outside_write_denied:outside,metadata_change_denied:metadata,owner_uid_escalation_denied:identity,nonpinned_exec_denied:true}));else setInterval(()=>{},1000);
  }else if(Date.now()>end){record('descendant_wait_timeout',null);clearInterval(timer);process.exitCode=3;}
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
let stage='caller_bootstrap',lastStep=null;
function diagnostic(error){
 let descendant=null;for(const line of String(lastStep?.stderr||'').split('\n')){try{const value=JSON.parse(line);if(value.qa_descendant_failure===true){descendant=value;break;}}catch{}}
 const code=value=>typeof value==='string'&&/^(?:[A-Za-z][A-Za-z0-9]*_[A-Za-z0-9_]{1,98}|EACCES|EPERM|ENOENT)$/.test(value)?value:null;
 const frames=[];const pattern=/\b(macos-command-runner|macos-workspace-session|verification-darwin-session|verification-darwin-client|macos-command-worker|macos-worker-envelope|flow|evaluation-harness)\.js:(\d+):(\d+)/g;
 for(const match of String(error.stack||'').matchAll(pattern)){if(frames.length===8)break;frames.push({file:match[1]+'.js',line:Number(match[2]),column:Number(match[3])});}
 return {stage,code:code(error.code),error_name:['Error','TypeError','RangeError','SyntaxError','AssertionError'].includes(error.name)?error.name:null,
  native_error_code:code(error.native_code||error.reply?.error||error.native_error||error.cause?.code),frames,
  step_failure_code:code(lastStep?.failure_code),step_exit:Number.isInteger(lastStep?.exit)?lastStep.exit:null,descendant};
}
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
 stage='caller_load_flow';const flow=require(path.join(q.source,'tools/flow.js'));let value;
 if(q.case==='normal_two_flow_steps'){
  stage='first_flow_await';
  const first=await flow.runOneAsync('macos-qa-step.js first',context,options);
  lastStep=first;stage='first_flow_assert';
  assert.equal(first.success,true);assert.equal(first.ownership.status,'completed');
  for(const name of ['qa-private0600','qa-renamed0600']){assert(fs.readFileSync(path.join(q.project,name),'utf8').length);fs.appendFileSync(path.join(q.project,name),'owner');}
  stage='second_flow_await';const second=await flow.runOneAsync('macos-qa-step.js second',context,options);
  lastStep=second;stage='second_flow_assert';
  assert.equal(second.success,true);assert.equal(second.ownership.status,'completed');
  assert.notEqual(first.parsed.uid,second.parsed.uid);value={first,second,owner_write_continuity:true};
 }else if(q.case==='evaluation_check'){
  stage='evaluation_check_await';
  value=await require(path.join(q.source,'tools/evaluation-harness.js')).runCheckAsync({name:'writable-continuity',command:'tools/macos-qa-step.js second'},options);
  assert.equal(value.status,'pass');assert.equal(value.ownership.status,'completed');
 }else if(q.case==='state_writer_fifo_read_cancel'){stage='state_fifo_flow_await';value=await flow.runFlowAsync({name:'lint',context},options);}
 else{stage='hold_flow_await';value=await flow.runOneAsync('macos-qa-step.js hold',context,options);}
 console.log(JSON.stringify({type:'result',ok:true,value}));
})().catch(error=>{console.log(JSON.stringify({type:'result',ok:false,code:error.code||'untyped',cleanup:error.cleanup||null,
 recovery_required:error.recovery_required===true,diagnostic:diagnostic(error)}));process.exitCode=2;});
"""

TEAM_CALLER = r"""'use strict';
const fs=require('node:fs'),path=require('node:path');const q=JSON.parse(fs.readFileSync(0,'utf8'));
let stage='team_context_prepare';
function diagnostic(error){
 const code=value=>typeof value==='string'&&/^(?:[A-Za-z][A-Za-z0-9]*_[A-Za-z0-9_]{1,98}|EACCES|EPERM|ENOENT)$/.test(value)?value:null;
 const frames=[],pattern=/\b(macos-command-runner|macos-workspace-session|verification-darwin-session|verification-darwin-client|macos-command-worker|macos-worker-envelope|contained-lock-manager|lock-publication|team-store|flow|evaluation-harness)\.js:(\d+):(\d+)/g;
 for(const match of String(error.stack||'').matchAll(pattern)){if(frames.length===8)break;frames.push({file:match[1]+'.js',line:Number(match[2]),column:Number(match[3])});}
 return {stage,code:code(error.code),error_name:['Error','TypeError','RangeError','SyntaxError','AssertionError'].includes(error.name)?error.name:null,
  native_error_code:code(error.native_code||error.reply?.error||error.native_error||error.cause?.code),
  native_errno:Number.isSafeInteger(error.native_error)&&error.native_error>=0&&error.native_error<=4095?error.native_error:null,frames};
}
try{
Object.assign(process.env,{KNOWLEDGE_DISABLE_GIT_DISCOVERY:'1',KNOWLEDGE_FLOW_NO_OPEN:'1',CI:'true',
 KNOWLEDGE_MACOS_WORKSPACE_ID:q.workspace_id,KNOWLEDGE_MACOS_BROKER_PATH:q.binary,KNOWLEDGE_MACOS_BROKER_SOCKET:q.socket});
delete process.env.KNOWLEDGE_STATE_ROOT;
const contextAPI=require(path.join(q.source,'tools/lib/path-context')),team=require(path.join(q.source,'tools/lib/team-store'));
const context=contextAPI.resolveKnowledgeContext({__skipCli:true,mode:'team',systemRoot:q.source,targetRoot:q.project,
 projectKnowledgeRoot:path.join(q.project,'.knowledge'),teamRoot:path.join(q.project,'team'),workspaceId:'macos-qa',agentId:'macos-ci'});
if(q.prepare){stage='team_register_prepare';team.registerWorkspace(context);console.log(JSON.stringify({type:'team_prepared',context,
 lock_path:team.lockPath(context.teamRoot,context.repoId),event_path:team.eventPath(context.teamRoot,context.repoId),
 workspace_path:team.workspaceDir(context.teamRoot,context.repoId,context.workspaceId)}));}
else{
 stage='team_main_await';
 const options={env:contextAPI.contextEnv(context),budgets:{setupMs:30000,workMs:120000,cleanupMs:30000,progressMs:0},
  macosWorkspace:{workspace_id:q.workspace_id,broker_path:q.binary,broker_socket:q.socket},
  onProgress:phase=>console.log(JSON.stringify({type:'progress',phase}))};
 require(path.join(q.source,'tools/flow')).mainAsync(['doctor','--exclusive','--json'],options).then(result=>{
  console.log(JSON.stringify({type:'result',ok:true,value:result.value,cleanup:result.cleanup,result}));
 },error=>{console.log(JSON.stringify({type:'result',ok:false,code:error.code||'untyped',cleanup:error.cleanup||null,diagnostic:diagnostic(error)}));process.exitCode=2;});
}
}catch(error){console.log(JSON.stringify({type:'result',ok:false,code:error.code||'untyped',diagnostic:diagnostic(error)}));process.exitCode=2;}
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
        'sha256': base.sha_file(item)} for item in sorted(stage.rglob('*'), key=lambda item: item.relative_to(stage).as_posix()) if item.is_file()]
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

    for name in CASES[:-1]:
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
                                observed = observe_fifo_reader(runner, helpers, actors['state_writer'], config_file,
                                    'macos-writable-actual-fifo-reader')
                                row['observations']['fifo_reader'] = observed
                                if observed['observed']: break
                                runner.check(process.poll() is None, 'macos_writable_fifo_controller_exited');time.sleep(.1)
                            runner.check(observed['observed'],
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
    run_team_case(runner, base, info, fixture, birth, send, entries, parse, helpers)


def run_team_case(runner, base, info, fixture, birth, send, entries, parse, helpers):
    # Native Team lock publication opens every ancestor as a read descriptor.
    # The disposable custody parent starts search-only; grant only read bits
    # on this exact root-owned fixture inode for this case, then restore it.
    current = runner.fixture.lstat()
    runner.check(stat.S_ISDIR(current.st_mode) and current.st_uid == 0 and stat.S_IMODE(current.st_mode) == 0o711 and
        current.st_dev == runner.fixture_identity['dev'] and current.st_ino == runner.fixture_identity['ino'],
        'macos_team_fixture_ancestor_identity')
    denied = False
    try:
        fd = os.open(runner.fixture, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        os.close(fd)
    except PermissionError as error:
        denied = error.errno == 13
    runner.check(denied, 'macos_team_fixture_read_control_not_denied')
    change = ('import os,stat,json,sys;p=sys.argv[1];e=json.loads(sys.argv[2]);old,new=map(int,sys.argv[3:]);'
        'fd=os.open(p,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW);s=os.fstat(fd);'
        'assert stat.S_ISDIR(s.st_mode) and s.st_uid==0 and s.st_dev==e["dev"] and s.st_ino==e["ino"] and stat.S_IMODE(s.st_mode)==old;'
        'os.fchmod(fd,new);s=os.fstat(fd);assert stat.S_IMODE(s.st_mode)==new and not s.st_mode&0o022;os.close(fd)')
    runner.root('macos-team-readable-fixture-ancestor', sys.executable, '-c', change,
        str(runner.fixture), json.dumps(runner.fixture_identity), str(0o711), str(0o755))
    try:
        fd = os.open(runner.fixture, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            opened = os.fstat(fd)
            runner.check(opened.st_dev == current.st_dev and opened.st_ino == current.st_ino and opened.st_uid == 0 and
                stat.S_IMODE(opened.st_mode) == 0o755, 'macos_team_fixture_read_control_identity')
        finally:
            os.close(fd)
        run_team_case_readable(runner, base, info, fixture, birth, send, entries, parse, helpers)
    finally:
        runner.root('macos-team-restore-fixture-ancestor', sys.executable, '-c', change,
            str(runner.fixture), json.dumps(runner.fixture_identity), str(0o755), str(0o711))
        if runner.case_results and runner.case_results[-1]['name'] == CASES[-1]:
            runner.case_results[-1]['observations']['fixture_ancestor_read_control'] = {
                'exact_root_owned_inode':True,'search_only_read_denied':True,'readable_read_confirmed':True,
                'write_permissions_unchanged':True,'original_mode_restored':True,'original_mode':0o711,'case_mode':0o755}


def run_team_case_readable(runner, base, info, fixture, birth, send, entries, parse, helpers):
    """Real abandoned Team lock -> automatic native closure -> public restart.

    Restart intentionally does not forge --retry-of for an incomplete run.
    That earlier durable run remains incomplete; the new run is distinct.
    """
    name = CASES[-1];started = time.monotonic();deadline = started+360
    row = {'name':name,'status':'FAIL','observations':{}};runner.case_results.append(row)
    project = fixture['project'];config = project/'.knowledge/config.yaml';saved = project/'.knowledge/config.before-team-fifo'
    caller = runner.evidence/'macos-team-recovery-caller.cjs';base.private_file(caller,TEAM_CALLER.encode())
    request = {key:str(fixture[key]) for key in ('source','project','workspace_id')}
    request.update(binary=str(info['binary']),socket=str(info['socket']))
    prepared = runner.run('macos-team-register-public-workspace',[str(info['node']),str(caller)],
        data=base.canonical({**request,'prepare':True}),timeout=30)
    row['controller_exit_code']=prepared.returncode
    if prepared.returncode != 0:
        try: row['terminal']=json.loads(prepared.stdout)
        except (ValueError,TypeError): pass
    setup = parse(prepared);runner.check(setup.get('type')=='team_prepared','macos_team_prepare_protocol')
    lock = Path(setup['lock_path']);workspace = Path(setup['workspace_path']);event_path = Path(setup['event_path'])
    for target in (lock,workspace,event_path):
        runner.check(target.is_relative_to(project/'team'),'macos_team_fixture_path_binding')
    original = config.read_bytes();text = original.decode('utf8')
    runner.check(text.count('updates:\n  enabled: true') == 1,'macos_team_updates_fixture_shape')
    configured = text.replace('updates:\n  enabled: true','updates:\n  enabled: false',1).encode()
    config.write_bytes(configured)
    base.private_file(runner.evidence/'TEAM_RECOVERY_INPUTS.json',base.canonical({
        'team_caller_sha256':base.sha_bytes(TEAM_CALLER.encode()),'original_config_sha256':base.sha_bytes(original),
        'configured_config_sha256':base.sha_bytes(configured),'updates_disabled':True,'expected_shipping_doctor_steps':8}))
    runner.check(not saved.exists(),'macos_team_fifo_backup_exists');config.rename(saved);os.mkfifo(config,0o600)
    fifo_fd = os.open(config,os.O_RDWR|os.O_NONBLOCK);before = set(entries());process = None;restored = False
    runner.public_started = True;runner.public_completed = False
    native_closures = []

    def closure(attempt,entry):
        end = min(deadline,time.monotonic()+35)
        while time.monotonic()<end:
            nonce = os.urandom(32).hex()
            value = runner.native_request(info,{'op':'observe_scope','attempt_id':attempt,
                'descriptor_sha256':entry['descriptor_sha256'],'observation_nonce':nonce},'macos-team-readonly-closure',timeout=10)
            if value.get('status')=='completed':break
            time.sleep(.1)
        runner.check(value.get('status')=='completed' and value.get('attempt_id')==attempt and
            value.get('descriptor_sha256')==entry['descriptor_sha256'] and value.get('observation_nonce')==nonce and
            value.get('schema')=='knowledge-darwin-scope-observation.v1' and value.get('cleanup_only') is True and
            value.get('proof_current') is False and value.get('observation_cached') is False and value.get('capability_qualified') is True and
            value.get('source_sha256')==runner.binaries['shipping']['source_sha256'] and all(value.get(key) is True for key in
            ('kernel_membership_zero','admission_closed','spawn_exclusion_acquired','spawn_intents_resolved',
             'guardian_exit_confirmed','root_child_exit_confirmed','registered_authority_exited','native_scope_closed')),
            'macos_team_native_closure_unconfirmed')
        native_closures.append(value);runner.task_uids.add(entry['descriptor']['task_ruid']);runner.expected_allocation_ids.add(attempt)
        observed = parse(runner.sudo(str(runner.uid_scan),str(entry['descriptor']['task_ruid']),name='macos-team-independent-uid-zero',timeout=15))
        runner.check(observed.get('observation_valid') is True and observed.get('member_count')==0,'macos_team_uid_not_empty')
        for role in ACTORS:
            runner.check(entry.get(role) and runner.compare_birth(entry[role]).get('state') in ('absent','replaced'),
                'macos_team_exact_actor_exit_unconfirmed')

    try:
        with (runner.evidence/'team-crash.stdout.raw').open('wb') as output,(runner.evidence/'team-crash.stderr.raw').open('wb') as error:
            process = subprocess.Popen([str(info['node']),str(caller)],stdin=subprocess.PIPE,stdout=output,stderr=error)
            runner.active_monitor=process;process.stdin.write(base.canonical(request));process.stdin.close();controller=birth(process.pid)
            old_entry = None;observed = None
            while time.monotonic()<deadline and process.poll() is None:
                candidates=[(key,value) for key,value in entries().items() if key not in before]
                if len(candidates)==1:
                    old_attempt,old_entry=candidates[0]
                    if all(old_entry.get(role) for role in ACTORS) and (lock/'owner.json').is_file() and (lock/'execution-scope.json').is_file():
                        observed=observe_fifo_reader(runner,helpers,old_entry['state_writer'],config,'macos-team-actual-fifo-reader')
                        row['observations']['fifo_reader']=observed
                        if observed['observed']:break
                time.sleep(.1)
            if process.poll() is not None:
                row['initial_controller_exit_code']=process.returncode
                try:
                    terminal_rows=[json.loads(line) for line in (runner.evidence/'team-crash.stdout.raw').read_bytes().splitlines()]
                    failures=[item for item in terminal_rows if item.get('type')=='result']
                    if len(failures)==1:row['terminal']=failures[0]
                except (ValueError,TypeError):pass
            runner.check(old_entry and (lock/'owner.json').is_file() and observed is not None and observed['observed'],
                'macos_team_lock_and_fifo_not_observed')
            old_owner_text=(lock/'owner.json').read_text();old_scope_text=(lock/'execution-scope.json').read_text()
            old_owner=json.loads(old_owner_text);old_scope=json.loads(old_scope_text)
            runner.check(old_owner.get('pid')==old_entry['state_writer']['pid'] and old_scope.get('backend')=='macos_uid_guardian' and
                old_scope['binding']['attempt_id']==old_attempt and old_scope['binding']['descriptor_sha256']==old_entry['descriptor_sha256'] and
                old_owner['execution_scope']['sha256']==base.sha_bytes(old_scope_text.encode()),'macos_team_old_lock_scope_binding')
            starts=list((workspace/'flow-runs').glob('*.start.json'));runner.check(len(starts)==1,'macos_team_old_run_count')
            old_start=json.loads(starts[0].read_bytes());old_run=old_start['run_id']
            runner.check(not (workspace/'flow-runs'/(old_run+'.final.json')).exists(),'macos_team_crash_run_already_finalized')
            send(controller,signal.SIGKILL);process.wait(timeout=15)
        runner.check(process.returncode==-signal.SIGKILL,'macos_team_controller_kill_not_observed')
        row['initial_controller_exit_code']=process.returncode;closure(old_attempt,old_entry)
        runner.check((lock/'owner.json').read_text()==old_owner_text and (lock/'execution-scope.json').read_text()==old_scope_text,
            'macos_team_lock_changed_before_public_restart')
        os.close(fifo_fd);fifo_fd=None;config.unlink();saved.rename(config);restored=True
        retry=runner.run('macos-team-public-restart',[str(info['node']),str(caller)],data=base.canonical(request),timeout=210)
        messages=[json.loads(line) for line in retry.stdout.splitlines()]
        terminals=[value for value in messages if value.get('type')=='result']
        row['controller_exit_code']=retry.returncode
        if len(terminals)==1:row['terminal']=terminals[0]
        runner.check(retry.returncode==0 and len(terminals)==1 and terminals[0].get('ok') is True,'macos_team_public_restart_failed')
        terminal=terminals[0];report=terminal['result'];out=report['value'];new_run=out.get('run_id')
        runner.check(new_run and new_run!=old_run and out.get('retry_of') is None and out.get('team_release',{}).get('status')=='released' and
            report.get('cleanup',{}).get('status')=='completed' and out.get('ownership',{}).get('status')=='completed' and
            out.get('command_cleanup',{}).get('status')=='completed' and out.get('command_authority_cleanup',{}).get('status')=='completed' and
            out.get('steps_total')==8 and isinstance(out.get('steps'),list) and len(out['steps'])==8 and
            any(value.get('type')=='progress' and value.get('phase')=='step_admitted' for value in messages),
            'macos_team_restart_ownership_or_execution_failed')
        created={key:value for key,value in entries().items() if key not in before}
        runner.check(len(created)==2,'macos_team_native_allocation_count');new_attempt=report['scope']['binding']['attempt_id']
        runner.check(new_attempt!=old_attempt and new_attempt in created,'macos_team_native_attempt_not_distinct')
        closure(new_attempt,created[new_attempt]);runner.check(not lock.exists(),'macos_team_new_lock_not_released')
        events=[json.loads(line) for line in event_path.read_text().splitlines() if line.strip()]
        acquired=[value for value in events if value.get('type')=='lock_acquired' and value.get('lock')=='flow']
        runner.check(len(acquired)==2 and acquired[0]['lock_id']==old_owner['lock_id'] and acquired[1]['lock_id']!=old_owner['lock_id'],
            'macos_team_new_lock_generation_not_distinct')
        quarantines=[item for item in (lock.parent/'.stale').glob('*/owner.json') if item.read_text()==old_owner_text]
        runner.check(len(quarantines)==1,'macos_team_old_generation_not_retained')
        quarantined_scope=(quarantines[0].parent/'execution-scope.json').read_text()
        runner.check(quarantined_scope==old_scope_text,'macos_team_quarantined_scope_changed')
        old_final_exists=(workspace/'flow-runs'/(old_run+'.final.json')).exists()
        new_start=json.loads((workspace/'flow-runs'/(new_run+'.start.json')).read_bytes())
        new_final=json.loads((workspace/'flow-runs'/(new_run+'.final.json')).read_bytes())
        runner.check(not old_final_exists and new_final.get('run_id')==new_run and new_final.get('release',{}).get('status')=='released',
            'macos_team_run_finalization_binding')
        team_doctor_report = capture_team_doctor_report(runner, base, runner.evidence, event_path.parents[3], new_start, out)
        proof={'old_owner_text':old_owner_text,'old_scope_text':old_scope_text,'quarantined_owner_text':quarantines[0].read_text(),
            'quarantined_scope_text':quarantined_scope,'old_start':old_start,'new_start':new_start,'new_final':new_final,
            'old_final_exists':old_final_exists,'team_events':events,'native_closures':native_closures,'retry_report':report,
            'team_doctor_report':team_doctor_report,'lock_absent':not lock.exists()}
        proof_bytes=base.canonical(proof);base.private_file(runner.evidence/'TEAM_RECOVERY_PROOF.private.json',proof_bytes)
        runner.check(fixture['outside'].read_bytes()==b'unchanged','macos_team_outside_canary_changed')
        row.update(controller_exit_code=retry.returncode,terminal={key:terminal[key] for key in ('type','ok','value','cleanup')},
            team_recovery_proof_sha256=base.sha_bytes(proof_bytes),quality_status=out['checks_status'],overall_status=out['overall_status'],
            elapsed_ms=(time.monotonic()-started)*1000,status='PASS_PHYSICAL_MACOS_WRITABLE')
        row['observations'].update(exact_actor_exits=True,independent_uid_zero=True,typed_native_closure=True,private_allocation_count=2,
            acceptance_after_cancel=False,automatic_native_cleanup=True,external_recovery_requested=False,outside_canary_unchanged=True,
            public_team_main_async=True,abandoned_lock_published=True,old_lock_scope_native_bound=True,old_native_scope_closed_before_restart=True,
            new_team_run_distinct=True,new_native_attempt_distinct=True,new_lock_generation_distinct=True,old_generation_quarantined_exact=True,
            old_run_remains_incomplete=True,new_team_lock_released=True,fresh_team_steps_executed=8,fresh_team_cleanup_completed=True,
            restart_not_retry_of=True,manual_owner_repair=False,actual_state_writer_fifo_fd_observed=True)
        runner.public_completed=True;runner.active_monitor=None
    finally:
        if fifo_fd is not None:os.close(fifo_fd)
        if runner.public_completed and restored:config.write_bytes(original)
        if process is not None and process.poll() is not None:runner.active_monitor=None


def main():
    target = Path(__file__).with_name('darwin-production-lifecycle.py')
    spec = importlib.util.spec_from_file_location('macos_writable_installation_owner', target)
    module = importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    sys.argv.extend(['--case-set', 'writable'])
    return module.main()


if __name__ == '__main__':
    raise SystemExit(main())
