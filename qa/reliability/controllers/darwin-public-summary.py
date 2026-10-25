#!/usr/bin/env python3
"""Build a strict public allowlist; never copy native replies or raw case output."""
import argparse, hashlib, json, math, os, re
from pathlib import Path

CASES=('normal','exit7','detached','silent-long','cancel','guardian-kill','daemon-kill',
       'paused-daemon-authority-loss','io-stop','root-phase-kill')
NATIVE=('verification-darwin-broker.m','verification-darwin-stub.c',
        'verification-darwin-transport.h','verification-darwin-uid-history.h','verification-darwin-uid-history.m')
HEX=re.compile(r'^[a-f0-9]{64}$')
FAILURES=set(('runner_architecture_mismatch independent_uid_observation_unavailable '
    'private_UID_not_empty_before_observation_deadline native_terminal_cleanup_unconfirmed '
    'detached_private_tree_not_observed restarted_daemon_not_observed controller_terminal_result_missing '
    'diagnostic_claimed_production held_actor_experiment_failed held_actor_facts_missing '
    'root_child_survived_guardian_death_before_setup old_daemon_epoch_receipt_was_current_success '
    'controller_process_exit_failed long_case_did_not_run_original_duration test_signal_compile_failed '
    'native_pin_drift compile_shipping_broker_failed compile_shipping_stub_failed compile_qa_broker_failed '
    'compile_qa_stub_failed stub_pair_mismatch_shipping stub_pair_mismatch_qa '
    'birth_observer_compile_failed uid_scan_compile_failed node_not_found node_exec_path_failed '
    'node_dylib_scan_failed native_birth_capture_mismatch native_birth_comparison_invalid '
    'native_birth_identity_changed direct_monitor_exit_unconfirmed source_mutated_during_run '
    'uid_scan_source_pin_mismatch birth_observer_source_missing evidence_root_exists evidence_root_permissions').split())
DIAGNOSTIC_FILES={'darwin-native-lifecycle.py','run_pipeline4.py','persistence_gate.py','external-frame'}
DIAGNOSTIC_TYPES={'QAError','FileNotFoundError','PermissionError','TypeError','AttributeError','KeyError','ValueError',
    'OSError','CalledProcessError','TimeoutExpired','RuntimeError','ImportError','ModuleNotFoundError','SyntaxError','KeyboardInterrupt','UnknownException'}
STAGES=set(('protect-fixture mode-fixture node-exec-path node-system-dylibs launchctl-print-own-label '
    'launchctl-verify-own-label-absent compile-uid-scan compile-birth-observer compile-test-signal '
    'read-own-protected-registry capture-native-process-birth compare-native-process-birth '
    'bootout-own-launchd-label confirm-own-broker-exit post-stop-private-uid-scan '
    'lstat-own-fixture-before-remove remove-own-fixture signal-owned-exact-birth '
    'independent-uid-observation fresh-recovery crash-own-launchd-daemon restart-own-launchd-daemon '
    'pause-own-launchd-daemon resume-own-launchd-daemon resume-own-launchd-daemon-during-cleanup').split())
def sha(value):return hashlib.sha256(value).hexdigest()
def number(value):return value if type(value) in (int,float) and math.isfinite(value) and value>=0 else None
def boolean(value):return value if type(value) is bool else None
def exit_code(value):return value if type(value) is int and -255<=value<=255 else None
def digest(value):return value if isinstance(value,str) and HEX.fullmatch(value) else None
def code(value):
    return value if isinstance(value,str) and (value in FAILURES or value in {'native_case_outcome_mismatch_'+case for case in CASES}) else 'controller_failure_details_private'
def stage_name(value):
    if not isinstance(value,str):return None
    matched=re.fullmatch(r'(\d{3})-(.+)',value)
    if not matched:return None
    suffix=matched[2]
    allowed=suffix in STAGES or re.fullmatch(r'(?:compile|describe)-(?:shipping|qa)-\d{2}-(?:broker|stub)',suffix) or \
        re.fullmatch(r'(?:init|bootstrap|install-plist)-(?:shipping|qa)',suffix) or \
        re.fullmatch(r'(?:install)-(?:shipping|qa)-(?:broker|stub|node)',suffix) or \
        re.fullmatch(r'(?:touch-log|mode-log)-(?:shipping|qa)-(?:stdout|stderr)',suffix) or \
        re.fullmatch(r'(?:mkdir|chown|chmod)-(?:bin|state|allocator|anchors|workspaces|control|qa|logs)',suffix)
    return value if allowed else matched[1]+'-unclassified-stage'
def read_json(file,maximum):
    try:
        if file.is_symlink() or not file.is_file() or file.stat().st_size>maximum:return None
        return json.loads(file.read_bytes())
    except (OSError,ValueError):return None
def excerpt(raw,redactions):
    text=raw[:32768].decode('utf8',errors='replace')
    for old,new in redactions:
        if old:text=text.replace(old,new)
    text=re.sub(r'\b(?:gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,})\b','<redacted-token>',text)
    text=re.sub(r'\b[a-fA-F0-9]{24,128}\b','<opaque-hex>',text)
    return '\n'.join(line[:300] for line in text.splitlines()[:8])[:1600]
def build(private,source,controller_status,architecture):
    raw=read_json(private/'SUMMARY.json',16*1024*1024)
    raw=raw if isinstance(raw,dict) else {}
    inputs=read_json(private/'INPUTS.json',2*1024*1024)
    inputs=inputs if isinstance(inputs,dict) else {}
    fallback=read_json(private/'DIAGNOSTIC.json',65536)
    diagnostics=[]
    candidates=raw.get('diagnostics',fallback.get('diagnostics',[]) if isinstance(fallback,dict) else [])
    for item in candidates[:4] if isinstance(candidates,list) else []:
        if not isinstance(item,dict):continue
        frames=[]
        for frame in item.get('frames',[])[:16] if isinstance(item.get('frames'),list) else []:
            if isinstance(frame,dict) and frame.get('file') in DIAGNOSTIC_FILES and type(frame.get('line')) is int and 0<frame['line']<1000000:
                frames.append({'file':frame['file'],'line':frame['line']})
        diagnostics.append({'type':item.get('type') if item.get('type') in DIAGNOSTIC_TYPES else 'UnknownException',
            'stage':item.get('stage') if item.get('stage') in ('bootstrap','execute','cleanup') else 'unknown','frames':frames})
    cases=[]
    for item in raw.get('cases',[]) if isinstance(raw.get('cases'),list) else []:
        if not isinstance(item,dict) or item.get('name') not in CASES:continue
        gate=item.get('gate') if isinstance(item.get('gate'),dict) else {}
        output={'name':item['name'],'status':item.get('status') if item.get('status') in
                ('PASS_PHYSICAL_NATIVE_DIAGNOSTIC','FAIL') else 'UNCONFIRMED',
            'elapsed_ms':number(item.get('elapsed_ms')),'expected_success':boolean(item.get('expected_success')),
            'source_sha256':digest(item.get('source_sha256')),'production_accepted':False,
            'events_sha256':digest(item.get('events_sha256')),'stderr_sha256':digest(item.get('stderr_sha256')),
            'failure_code':code(item['reason']) if 'reason' in item else None,
            'held_actor_facts_before_release':boolean(gate.get('facts_observed_before_release')),
            'root_child_exit_before_release':boolean(gate.get('root_child_exit_confirmed'))}
        for key in ('uid_empty_while_actor_held','uid_empty_before_daemon_resume'):
            observation=gate.get(key) if isinstance(gate.get(key),dict) else {}
            output[key]={'zero':boolean(observation.get('zero')),'elapsed_ms':number(observation.get('elapsed_ms'))}
        cases.append(output)
    native={}
    for name in NATIVE:
        p=source/'tools/lib'/name
        if p.is_file() and not p.is_symlink():native[name]=sha(p.read_bytes())
    histories=[]
    for item in raw.get('binary_history',[]) if isinstance(raw.get('binary_history'),list) else []:
        if not isinstance(item,dict):continue
        row={key:digest(item.get(key)) for key in ('broker_sha256','stub_sha256','source_sha256','stub_source_sha256','qa_build_id')}
        row['kind']=item.get('kind') if item.get('kind') in ('qa','shipping') else 'unknown'
        row['qa_io_enabled']=boolean(item.get('qa_io_enabled'));histories.append(row)
    stages=[];compile_diagnostics=[]
    redactions=[(str(source),'<pinned-source>'),(str(private),'<private-evidence>'),
        (str(private.parent),'<private-root>'),(os.environ.get('GITHUB_WORKSPACE',''),'<workspace>'),
        (os.environ.get('RUNNER_TEMP',''),'<runner-temp>')]
    for item in raw.get('records',[]) if isinstance(raw.get('records'),list) else []:
        if not isinstance(item,dict):continue
        name=item.get('name');public_name=stage_name(name)
        # Stage names are generated by the reviewed controller, not payload data.
        if public_name is None:continue
        stages.append({'stage':public_name,'stage_name_sha256':sha(name.encode()),'exit_code':exit_code(item.get('exit_code')),
            'timed_out':boolean(item.get('timed_out')),'elapsed_ms':number(item.get('elapsed_ms')),
            'stdout_sha256':digest(item.get('stdout_sha256')),'stderr_sha256':digest(item.get('stderr_sha256'))})
        if public_name==name and re.fullmatch(r'\d{3}-compile-[A-Za-z0-9_.-]{1,80}',name):
            stderr=private/(name+'.stderr.raw')
            if stderr.is_file() and not stderr.is_symlink() and stderr.stat().st_size<=4*1024*1024:
                compile_diagnostics.append({'stage':name,'stderr_excerpt':excerpt(stderr.read_bytes(),redactions)})
    passed=controller_status==0 and raw.get('status')=='PASS_PHYSICAL_NATIVE_DIAGNOSTIC_ONLY' and raw.get('source_unchanged') is True and raw.get('architecture')==architecture
    names=[row['name'] for row in cases]
    full=names==list(CASES[:8])+list(CASES[8:]) and all(row['status']=='PASS_PHYSICAL_NATIVE_DIAGNOSTIC' for row in cases)
    summary={'schema':'knowledge-reliability-darwin-public.v1','status':'PASS_NATIVE_DIAGNOSTIC_MATRIX' if passed and full else 'FAIL_OR_INCOMPLETE',
        'controller_exit_code':controller_status,'expected_architecture':architecture,
        'architecture':raw.get('architecture') if raw.get('architecture') in ('x86_64','arm64') else None,
        'source_unchanged':boolean(raw.get('source_unchanged')),'source_pins':native,
        'source_manifest_sha256':sha(json.dumps(inputs['files'],ensure_ascii=False,sort_keys=True,separators=(',',':')).encode()) if isinstance(inputs.get('files'),list) else None,
        'source_manifest_file_count':len(inputs['files']) if isinstance(inputs.get('files'),list) else None,
        'controller_sha256':digest(inputs.get('controller_sha256')),'test_signal_sha256':digest(inputs.get('test_signal_sha256')),
        'reference_runner_sha256':digest(inputs.get('reference_runner_sha256')),
        'failure_code':code(raw['failure']) if raw.get('failure') else (None if raw else 'controller_summary_missing'),
        'cases':cases,'compiled_pairs':histories,'compiler_diagnostics':compile_diagnostics,'diagnostics':diagnostics,
        'workflow_commit':os.environ.get('GITHUB_SHA') if re.fullmatch(r'[a-f0-9]{40}',os.environ.get('GITHUB_SHA','')) else None,
        'workflow_run_id':os.environ.get('GITHUB_RUN_ID') if re.fullmatch(r'\d+',os.environ.get('GITHUB_RUN_ID','')) else None,
        'native_os_origin_qualified':False,'backend_qualified':False,'production_KVE_KVF_ACK':'NOT_RUN',
        'actual_kernel_IO_stall':'NOT_RUN; compile-time QA holds do not simulate a kernel storage driver',
        'raw_evidence_scope':'runner-private only; raw payload output, nonce, token, paths and native replies excluded'}
    return summary,{'schema':'knowledge-reliability-darwin-public-stages.v1','stages':stages}
def main():
    ap=argparse.ArgumentParser();ap.add_argument('--private',required=True);ap.add_argument('--public',required=True)
    ap.add_argument('--source',required=True);ap.add_argument('--controller-status',required=True,type=int)
    ap.add_argument('--expected-arch',required=True,choices=('arm64','x86_64'));args=ap.parse_args()
    private=Path(args.private).resolve();source=Path(args.source).resolve();public=Path(args.public).resolve()
    if public==private or public.is_relative_to(private) or private.is_relative_to(public):raise SystemExit('public_private_overlap')
    summary,stages=build(private,source,args.controller_status,args.expected_arch)
    public.mkdir(mode=0o755,parents=True,exist_ok=False)
    for name,value in (('summary.json',summary),('stages.json',stages)):
        p=public/name;p.write_text(json.dumps(value,indent=2,sort_keys=True)+'\n');p.chmod(0o644)
    print(json.dumps({'status':summary['status'],'public_files':['summary.json','stages.json'],
        'backend_qualified':False,'raw_uploaded':False}))
    # The public decision is an independent acceptance gate. A zero exit from
    # a controller with missing/duplicate cases, wrong architecture or source
    # drift must not turn this workflow green. Keep both JSON files on FAIL.
    return 0 if summary['status']=='PASS_NATIVE_DIAGNOSTIC_MATRIX' else 1
if __name__=='__main__':raise SystemExit(main())
