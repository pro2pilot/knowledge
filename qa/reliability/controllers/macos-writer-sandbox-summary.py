#!/usr/bin/env python3
"""Strict boundary-only projection; never claims shipping Flow qualification."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
HERE=Path(__file__).resolve().parent

def module(name,path):
    spec=importlib.util.spec_from_file_location(name,path);value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value
legacy=module('writer_public_helpers',HERE/'darwin-production-summary.py')
fixture=module('writer_fixed_fixture',HERE/'macos-writer-sandbox-lifecycle.py')
sha=lambda b:hashlib.sha256(b).hexdigest()
canonical=lambda v:json.dumps(v,ensure_ascii=False,sort_keys=True,separators=(',',':')).encode()
obj=lambda v:v if isinstance(v,dict) else {}
hex64=lambda v:isinstance(v,str) and re.fullmatch(r'[a-f0-9]{64}',v) is not None
FACTS=('original_uid_writer','original_owner_setuid_positive_control','private_uid_setuid_exec_denied',
    'inside_control_write_succeeded','owner_outside_write_control_succeeded','actual_checked_directory_replaced',
    'outside_write_denied_by_native_profile','outside_unchanged','exact_actor_exits','independent_uid_zero',
    'automatic_native_cleanup','qa_derived_native_boundary_only')
SOURCE_NAMES={'source_sha256':'verification-darwin-broker.m','stub_source_sha256':'verification-darwin-stub.c','transport_header_sha256':'verification-darwin-transport.h','uid_history_header_sha256':'verification-darwin-uid-history.h','uid_history_source_sha256':'verification-darwin-uid-history.m'}
ASSETS=('macos-writer-sandbox-lifecycle.py','macos-workspace-provision.c','macos-owner-exec-canary.c')

def exact_file(file,digest):
    return file.is_file() and not file.is_symlink() and hex64(digest) and sha(file.read_bytes())==digest

def package_valid(private,source,rows,special,addon,arch):
    stage=private/'macos-writer-package-stage';members=special.get('protected_package_members')
    if not isinstance(members,list) or not members or special.get('protected_package_sha256')!=sha(canonical(members)):return False
    expected={row['path'].removeprefix(source.name+'/'):{key:row[key] for key in ('bytes','sha256')} for row in rows}
    expected['tools/lib/macos-command-worker.js']={'bytes':len(fixture.WORKER.encode()),'sha256':sha(fixture.WORKER.encode())}
    directory='tools/lib/native/darwin-'+('x64' if arch=='x86_64' else 'arm64')
    manifest=stage/directory/'lock-publication.manifest.json'
    if manifest.is_symlink() or legacy.load(manifest,16384)!=addon:return False
    expected[directory+'/lock-publication.manifest.json']={'bytes':manifest.stat().st_size,'sha256':sha(manifest.read_bytes())}
    expected[directory+'/lock-publication.node']={'bytes':addon['binary_bytes'],'sha256':addon['binary_sha256']}
    actual={}
    for row in members:
        if not isinstance(row,dict) or set(row)!={'path','bytes','sha256'}:return False
        name=row['path']
        if not isinstance(name,str) or not name or Path(name).is_absolute() or '\\' in name or any(p in ('','.','..') for p in name.split('/')) or name in actual:return False
        if type(row['bytes']) is not int or row['bytes']<0 or not hex64(row['sha256']):return False
        actual[name]={k:row[k] for k in ('bytes','sha256')}
    if actual!=expected or [row['path'] for row in members]!=sorted(actual):return False
    physical=[]
    for file in sorted(stage.rglob('*')):
        if file.is_symlink():return False
        if file.is_file():
            if file.stat().st_nlink!=1:return False
            physical.append({'path':file.relative_to(stage).as_posix(),'bytes':file.stat().st_size,'sha256':sha(file.read_bytes())})
    return physical==members and special.get('package_derivation')==fixture.DERIVATION

def proof_valid(proof,row,special):
    scope=obj(proof.get('scope'));binding=obj(scope.get('binding'));d=obj(binding.get('descriptor'))
    native=obj(proof.get('native_closure'));probe=obj(proof.get('probe'));owner=obj(special.get('owner_control'));execproof=obj(proof.get('owner_exec'))
    writer=obj(proof.get('writer_exit'));authority=obj(proof.get('authority_exit'));births=obj(proof.get('births'))
    if proof.get('automatic_native_cleanup') is not True or proof.get('external_recovery_requested') is not False:return False
    if d.get('attempt_id')!=binding.get('attempt_id'):return False
    if proof.get('ok') is not True or proof.get('attempt_id')!=binding.get('attempt_id') or not hex64(binding.get('attempt_id')) or binding.get('descriptor_sha256')!=sha(canonical(d)):return False
    if scope.get('schema_version')!='knowledge-command-scope.v1' or scope.get('backend')!='macos_uid_guardian' or d.get('schema')!='knowledge-macos-writable-descriptor.v1' or d.get('mode')!='admin_writable_workspace.v1':return False
    if type(d.get('task_ruid')) is not int or not 1000000000<=d['task_ruid']<1900000000:return False
    if type(owner.get('ruid')) is not int or owner['ruid']<=0 or owner.get('euid')!=owner['ruid'] or special.get('owner_canary_installed_uid')!=owner['ruid'] or type(special.get('owner_canary_installed_mode')) is not int or special['owner_canary_installed_mode']!=0o4755:return False
    if probe.get('uid')!=owner['ruid'] or probe.get('uid')==d['task_ruid'] or probe.get('pid')!=obj(obj(births.get('writer')).get('writer')).get('pid') or probe.get('inside_control') is not True or probe.get('outside_errno') not in ('EACCES','EPERM'):return False
    if execproof.get('uid')!=d['task_ruid'] or execproof.get('denied') is not True or execproof.get('errno') not in ('EACCES','EPERM') or execproof.get('status') is not None or execproof.get('stdout')!='':return False
    cmd=obj(proof.get('owner_exec_command'));cp=obj(obj(cmd.get('cleanup')).get('proof'))
    if type(cmd.get('status')) is not int or cmd['status']!=0 or obj(cmd.get('cleanup')).get('status')!='completed' or cp.get('command_cleanup_confirmed') is not True or cp.get('kernel_membership_zero') is not True:return False
    if proof.get('checked_directory')!=proof.get('renamed_directory') or not isinstance(proof.get('checked_directory'),dict) or set(proof['checked_directory'])!={'dev','ino'} or any(not isinstance(v,str) or not v.isdecimal() for v in proof['checked_directory'].values()):return False
    if not isinstance(obj(proof.get('substituted_symlink')).get('target'),str) or proof.get('outside_unchanged') is not True:return False
    if writer.get('writer_exit_observed') is not True or type(writer.get('code')) is not int or writer['code']!=0 or writer.get('signal') is not None or writer.get('writer_sandbox')!='workspace.v1' or not isinstance(d.get('writable_root'),str) or writer.get('writable_root_sha256')!=sha(d['writable_root'].encode()):return False
    if authority.get('writer_exit_observed') is not True or authority.get('signal')!='SIGKILL':return False
    actors=obj(proof.get('actor_observations'))
    if set(actors)!={'authority','authority_guardian','state_writer','state_guardian','controller'} or any(obj(v).get('state') not in ('absent','replaced') or obj(v).get('schema')!='knowledge-darwin-qa-birth.v1' or type(obj(v).get('pid')) is not int or v['pid']<=0 for v in actors.values()):return False
    registered=obj(proof.get('registered_actors'))
    if set(registered)!=set(actors) or any(obj(registered[k]).get('pid')!=actors[k]['pid'] for k in actors):return False
    for role,prefix in (('authority','authority'),('state_writer','writer')):
        if obj(obj(births.get(prefix)).get('writer')).get('pid')!=actors[role]['pid'] or obj(obj(births.get(prefix)).get('guardian')).get('pid')!=actors['authority_guardian' if role=='authority' else 'state_guardian']['pid']:return False
    uid=obj(proof.get('independent_uid_scan'))
    if uid.get('uid')!=d['task_ruid'] or type(uid.get('errno')) is not int or uid['errno']!=0 or uid.get('members')!=[]:return False
    if uid.get('observation_valid') is not True or type(uid.get('member_count')) is not int or uid['member_count']!=0:return False
    if native.get('schema')!='knowledge-darwin-scope-observation.v1' or native.get('status')!='completed' or native.get('state')!='closed' or native.get('attempt_id')!=binding['attempt_id'] or native.get('descriptor_sha256')!=binding['descriptor_sha256'] or not hex64(proof.get('observation_nonce')) or native.get('observation_nonce')!=proof['observation_nonce']:return False
    for key in ('ok','cleanup_only','capability_qualified','cleanup_observation_current','registry_healthy','allocation_tuple_verified_current','kernel_membership_zero','admission_closed','spawn_exclusion_acquired','spawn_intents_resolved','guardian_exit_confirmed','root_child_exit_confirmed','registered_authority_exited','native_scope_closed','clock_healthy'):
        if native.get(key) is not True:return False
    for key in ('proof_current','observation_cached','qualification_mode','qa_persistence_gate','active_attempt'):
        if native.get(key) is not False:return False
    return all(native.get(k)==d.get(k) and hex64(native.get(k)) for k in ('source_sha256','stub_source_sha256'))

def native_tuple_valid(proof,native,source):
    d=obj(obj(obj(proof.get('scope')).get('binding')).get('descriptor'));c=obj(proof.get('capability'));v=obj(proof.get('native_closure'))
    expected={k:sha((source/'tools/lib'/name).read_bytes()) for k,name in SOURCE_NAMES.items()}
    expected.update(binary_sha256=native.get('broker_sha256'),stub_binary_sha256=native.get('stub_sha256'))
    if any(not hex64(want) or v.get(k)!=want or c.get(k)!=want or d.get('broker_binary_sha256' if k=='binary_sha256' else k)!=want for k,want in expected.items()):return False
    for k in ('host_id','boot_id'):
        if not isinstance(d.get(k),str) or not re.fullmatch(r'[a-fA-F0-9]{8}(?:-[a-fA-F0-9]{4}){3}-[a-fA-F0-9]{12}',d[k]) or v.get(k)!=d[k] or c.get(k)!=d[k]:return False
    for k in ('daemon_epoch','installation_id','account_policy_sha256'):
        if not hex64(d.get(k)) or v.get(k)!=d[k] or c.get(k)!=d[k]:return False
    if d.get('account_policy_id')!='admin_reserved_interval_no_runtime_nss.v1' or v.get('account_policy_id')!=d['account_policy_id'] or c.get('account_policy_id')!=d['account_policy_id']:return False
    if not hex64(d.get('allocation_sha256')) or d.get('allocation_seq')!=str(d['task_ruid']-1000000000+1):return False
    if any(v.get(k)!=d.get(k) for k in ('allocation_seq','allocation_sha256','task_ruid')):return False
    if type(v.get('observed_monotonic_ms')) is not int or v['observed_monotonic_ms']<0 or v.get('lifecycle_basis')!='same_boot_terminal' or v.get('historical_terminal_before_new_boot') is not False or v.get('reboot_recovery_confirmed') is not False:return False
    return True

def build(private,source,rc,arch):
    raw=legacy.load(private/'SUMMARY.json');inputs=legacy.load(private/'INPUTS.json');special=legacy.load(private/'MACOS_WRITER_SANDBOX_INPUTS.json')
    rows=inputs.get('files',[]);cases=raw.get('cases',[]);case=obj(cases[0]) if isinstance(cases,list) and len(cases)==1 else {};obs=obj(case.get('observations'))
    proofpath=private/'MACOS_WRITER_SANDBOX_PROOF.private.json';proof=legacy.load(proofpath,4*1024*1024)
    checks={'exact_source_inventory':legacy.input_inventory_valid(source,rows),'exact_case_inventory':len(cases)==1 and case.get('name')==fixture.CASE,
        'source_unchanged':raw.get('source_unchanged') is True,'cleanup_confirmed':raw.get('cleanup_confirmed') is True,
        'fixture_assets':inputs.get('writer_sandbox_assets')=={name:sha((HERE/name).read_bytes()) for name in ASSETS},
        'lifecycle':inputs.get('lifecycle_sha256')==sha((HERE/'darwin-production-lifecycle.py').read_bytes()),
        'node_controller':inputs.get('controller_sha256')==sha((HERE/'darwin-production-controller.js').read_bytes()),
        'reference_runner':inputs.get('reference_runner_sha256')==sha((HERE.parent/'reference/qa/darwin-pipeline4/run_pipeline4.py').read_bytes()),
        'worker':special.get('worker_sha256')==sha(fixture.WORKER.encode()),'caller':special.get('caller_sha256')==sha(fixture.CALLER.encode()) and exact_file(private/'macos-writer-sandbox-caller.cjs',sha(fixture.CALLER.encode())),
        'provision':special.get('provision_source_sha256')==sha((HERE/'macos-workspace-provision.c').read_bytes()) and exact_file(private/'macos-writer-provision',special.get('provision_binary_sha256')),
        'owner_canary':special.get('owner_canary_source_sha256')==sha((HERE/'macos-owner-exec-canary.c').read_bytes()) and exact_file(private/'macos-owner-exec-canary',special.get('owner_canary_binary_sha256')),
        'proof_bytes':exact_file(proofpath,case.get('proof_sha256')) and case.get('terminal')==proof,'proof_contract':proof_valid(proof,case,special)}
    history=raw.get('binary_history',[]);native=obj(history[0]) if isinstance(history,list) and len(history)==1 else {}
    checks['native_build']=native.get('kind')=='shipping' and native.get('qa_io_enabled') is False and all(native.get(key)==sha((source/'tools/lib'/file).read_bytes()) for key,file in (('source_sha256','verification-darwin-broker.m'),('stub_source_sha256','verification-darwin-stub.c'))) and all(exact_file(private/(role+'-shipping-01'),native.get(role+'_sha256')) for role in ('broker','stub'))
    addon=obj(raw.get('native_addon'));checks['native_addon']=addon.get('schema_version')=='knowledge-lock-native-binary.v1' and addon.get('platform')=='darwin' and addon.get('architecture')==('x64' if arch=='x86_64' else 'arm64') and addon.get('napi_version')==8 and addon.get('source_sha256')==sha((source/'tools/native/lock-publication.c').read_bytes())
    checks['protected_package']=package_valid(private,source,rows,special,addon,arch)
    installed=raw.get('installed_bindings',[]);checks['installed_bindings']=isinstance(installed,list) and len(installed)==3 and {obj(v).get('role') for v in installed}=={'broker','stub','node'} and all(hex64(obj(v).get('source_sha256')) and v['source_sha256']==v.get('installed_sha256') and (v['role']=='node' or v['source_sha256']==native.get(v['role']+'_sha256')) for v in installed)
    d=obj(obj(obj(proof.get('scope')).get('binding')).get('descriptor'));checks['proof_native_binding']=native_tuple_valid(proof,native,source)
    checks.update({key:obs.get(key) is True for key in FACTS})
    checks['boundary_only']=obs.get('shipping_flow_proof') is False and obs.get('external_recovery_requested') is False and type(obs.get('private_allocation_count')) is int and obs['private_allocation_count']==1
    passed=type(rc) is int and rc==0 and raw.get('status')==fixture.STATUS and case.get('status')==fixture.STATUS and type(case.get('controller_exit_code')) is int and case['controller_exit_code']==0 and raw.get('case_set')=='writable-sandbox' and raw.get('architecture')==arch and all(checks.values())
    return {'schema':'knowledge-macos-writer-sandbox-public.v1','status':fixture.STATUS if passed else 'FAIL_OR_INCOMPLETE','checks':checks,'expected_architecture':arch,'controller_exit_code':rc,'source_inventory_sha256':sha(canonical(rows)),'source_file_count':len(rows),'release_gate_qualified':False,'shipping_flow_proof':False,'scope':'Fixed QA writer and private-RUID executable boundary only; original-owner symlink substitution and original-owner setuid executable denial. No shipping Flow acceptance claim.'}

def main():
    p=argparse.ArgumentParser();p.add_argument('--private',required=True);p.add_argument('--public',required=True);p.add_argument('--source',required=True);p.add_argument('--controller-status',type=int,required=True);p.add_argument('--expected-arch',choices=('x86_64','arm64'),required=True);a=p.parse_args();out=Path(a.public);out.mkdir(parents=True,exist_ok=False)
    try:result=build(Path(a.private),Path(a.source),a.controller_status,a.expected_arch)
    except (OSError,KeyError,TypeError,ValueError,IndexError):result={'schema':'knowledge-macos-writer-sandbox-public.v1','status':'FAIL_OR_INCOMPLETE','failure_codes':['projection_input_invalid'],'shipping_flow_proof':False,'release_gate_qualified':False}
    (out/'summary.json').write_text(json.dumps(result,indent=2,sort_keys=True)+'\n');print(json.dumps({'status':result['status'],'shipping_flow_proof':False,'release_gate_qualified':False}));return 0 if result['status']==fixture.STATUS else 1
if __name__=='__main__':raise SystemExit(main())
