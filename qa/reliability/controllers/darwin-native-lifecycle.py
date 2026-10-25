#!/usr/bin/env python3
"""Physical Darwin lifecycle experiments on the exact supplied source tree.

Reuses the pinned reference's fixture installer/cleanup, never its verdict or
pins. Shipping physics and compile-time QA holds are reported separately.
No KVE/KVF/ACK is produced here. Production integration has its own controller.
"""
import argparse, hashlib, importlib.util, json, os, platform, queue, signal, subprocess, sys, threading, time, traceback, uuid
from pathlib import Path

DIAGNOSTIC_FILES={'darwin-native-lifecycle.py','run_pipeline4.py','persistence_gate.py'}
DIAGNOSTIC_TYPES={'QAError','FileNotFoundError','PermissionError','TypeError','AttributeError','KeyError','ValueError',
    'OSError','CalledProcessError','TimeoutExpired','RuntimeError','ImportError','ModuleNotFoundError','SyntaxError','KeyboardInterrupt'}
def safe_exception(error,stage):
    frames=[];current=error.__traceback__
    while current is not None and len(frames)<16:
        name=Path(current.tb_frame.f_code.co_filename).name
        frames.append({'file':name if name in DIAGNOSTIC_FILES else 'external-frame','line':current.tb_lineno})
        current=current.tb_next
    # No message, args, source line, local variable or pathname enters this view.
    return {'type':type(error).__name__ if type(error).__name__ in DIAGNOSTIC_TYPES else 'UnknownException',
        'stage':stage if stage in ('bootstrap','execute','cleanup') else 'unknown','frames':frames}

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--source', required=True)
    ap.add_argument('--reference', required=True, help='Directory containing qa/darwin-pipeline4')
    ap.add_argument('--evidence', required=True)
    ap.add_argument('--expected-arch', required=True)
    ap.add_argument('--cases', default='normal,exit7,detached,silent-long,cancel,guardian-kill,daemon-kill,paused-daemon-authority-loss,io-stop,root-phase-kill')
    args = ap.parse_args()
    if platform.system() != 'Darwin':
        result = {'status': 'NOT_RUN_DARWIN_REQUIRED', 'capability_qualified': False,
            'platform': platform.platform(), 'architecture': platform.machine(), 'argv': sys.argv,
            'controller_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
        output = Path(args.evidence).resolve();output.mkdir(parents=True, exist_ok=False)
        (output/'SUMMARY.json').write_text(json.dumps(result, indent=2)+'\n')
        print(json.dumps(result))
        return 2
    reference = Path(args.reference).resolve()
    module_path = reference / 'qa/darwin-pipeline4/run_pipeline4.py'
    sys.path.insert(0, str(module_path.parent))
    spec = importlib.util.spec_from_file_location('pinned_fixture_utilities', module_path)
    base = importlib.util.module_from_spec(spec);spec.loader.exec_module(base)
    evidence = Path(args.evidence).resolve()
    source = Path(args.source).resolve()
    controller = Path(__file__).with_name('darwin-native-controller.js').resolve()
    signal_source = Path(__file__).with_name('darwin-test-signal.c').resolve()
    cases = args.cases.split(',')
    class Runner(base.Runner):
        def __init__(self):
            super().__init__(module_path.parent / 'PINS.json', evidence, args.expected_arch, evidence / 'public')
            self.workspace = reference
            self.source = source.parent
            self.case_results = []
            self.input_pins = []
            for p in sorted(source.rglob('*')):
                if p.is_file() and not p.is_symlink():
                    self.input_pins.append({'path': p.relative_to(source.parent).as_posix(), 'bytes': p.stat().st_size, 'sha256': base.sha_file(p)})
            native = {name: '.knowledge/tools/lib/' + file for name, file in {
                'broker': 'verification-darwin-broker.m', 'stub': 'verification-darwin-stub.c',
                'history_header': 'verification-darwin-uid-history.h', 'history_source': 'verification-darwin-uid-history.m',
                'transport_header': 'verification-darwin-transport.h'}.items()}
            self.pins = {'files': self.input_pins, 'native': native,
                'qa': {'build_id': base.sha_bytes(base.canonical(self.input_pins)), 'socket_relative': 'qa/gate.sock'}}
            self.account_policy = 'admin_reserved_interval_no_runtime_nss.v1'
            self.task_uids = set()
            self.signal_binary = evidence / 'exact-test-signal'
        def checked_signal(self, identity, uid, image, sig):
            self.capture_birth(identity, uid, str(image))
            self.root('signal-owned-exact-birth', str(self.signal_binary), str(identity['pid']), identity['unique_id'],
                str(identity['start_sec']), str(identity['start_usec']), str(uid), str(sig), str(image))
        def scan(self, uid):
            p = self.sudo(str(self.uid_scan), str(uid), name='independent-uid-observation', timeout=10)
            try: value = json.loads(p.stdout)
            except Exception: value = None
            self.check(isinstance(value, dict) and value.get('observation_valid') is True and p.returncode in (0, 1),
                'independent_uid_observation_unavailable')
            return value
        def wait_empty(self, uid, allowance=30):
            start = time.monotonic()
            while time.monotonic() - start < allowance:
                value = self.scan(uid)
                if value['member_count'] == 0:
                    return {'zero': True, 'elapsed_ms': (time.monotonic()-start)*1000, 'scope': 'fresh-kernel-UID-list'}
                time.sleep(.1)
            raise base.QAError('private_UID_not_empty_before_observation_deadline')
        def wait_terminal(self, info, binding):
            end = time.monotonic()+90
            while time.monotonic()<end:
                try:
                    value = self.native_request(info, {'op': 'recover', 'attempt_id': binding['attempt_id'],
                        'descriptor_sha256': binding['descriptor_sha256'], 'cleanup_budget_ms': 60000}, 'fresh-recovery', timeout=70)
                    if value.get('state')=='closed' and value.get('proof', {}).get('native_cleanup_facts_confirmed') is True:
                        return value
                except base.QAError:
                    pass
                time.sleep(.2)
            raise base.QAError('native_terminal_cleanup_unconfirmed')
        def script(self, case):
            if case == 'normal': return "console.log('native-normal');\n"
            if case == 'exit7': return "process.exitCode=7;\n"
            if case == 'silent-long': return "setTimeout(()=>process.exit(0),125000);\n"
            # The parent, child and grandchild use distinct process groups and
            # leave no writable marker in the sealed source tree.
            child = "const{spawn}=require('node:child_process');const g=spawn(process.execPath,['-e','setInterval(()=>{},1000)'],{detached:true,stdio:'ignore'});g.unref();process.stdout.write('ready\\n');setInterval(()=>{},1000);"
            return "const{spawn}=require('node:child_process');const c=spawn(process.execPath,['-e',"+json.dumps(child)+"],{detached:true,stdio:['ignore','pipe','ignore']});c.stdout.once('data',()=>{console.log('NATIVE_READY '+JSON.stringify({pid:process.pid,child:c.pid}));c.stdout.destroy();c.unref();"+("setTimeout(()=>process.exit(0),1500);" if case=='detached' else "setInterval(()=>{},1000);")+"});\n"
        def case(self, name, info):
            begin=time.monotonic();project=evidence/('project-'+name);project.mkdir(mode=0o700)
            (project/'run.js').write_text(self.script(name))
            output=evidence/(name+'.events.jsonl');stderr=evidence/(name+'.controller.stderr')
            messages=queue.Queue();all_events=[];binding=None;acted=False;terminal=None;gate_thread=None;gate_result={};daemon_paused=False
            controller_runtime=str(self.node_path())
            process=subprocess.Popen([controller_runtime,str(controller)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,
                stderr=stderr.open('wb'),text=True,encoding='utf-8',bufsize=1)
            self.active_monitor=process
            def reader():
                with output.open('w',encoding='utf8') as saved:
                    for line in process.stdout:
                        saved.write(line);saved.flush()
                        try: message=json.loads(line)
                        except Exception: message={'type':'invalid','line_sha256':base.sha_bytes(line.encode())}
                        all_events.append(message);messages.put(message)
                messages.put({'type':'eof'})
            threading.Thread(target=reader,daemon=True).start()
            config={key:str(info[key]) for key in ('binary','socket','node')}
            process.stdin.write(json.dumps({'source':str(source),'project':str(project),'config':config,
                'work_ms':360000,'command_ms':240000,'cleanup_ms':60000,'expected_exit':7 if name=='exit7' else 0})+'\n');process.stdin.flush()
            def signal_stop():
                process.stdin.write('{"op":"stop"}\n');process.stdin.flush()
            def pending(entered):
                try:
                    gate_result['entered']=True;gate_result['broker_pid']=entered['broker_pid']
                    if name=='root-phase-kill':
                        state=self.fixture_registry_snapshot();entry=state['attempts'][binding['attempt_id']]
                        root_child=entry['root_child'];guardian=entry['launch_stub']
                        self.capture_birth(root_child,0,str(info['stub']));self.checked_signal(guardian,0,info['stub'],signal.SIGKILL)
                        deadline=time.monotonic()+30
                        while time.monotonic()<deadline:
                            observation=self.compare_birth(root_child)
                            if observation['state'] in ('absent','replaced'):
                                gate_result['root_child_exit_confirmed']=True;break
                            time.sleep(.1)
                        self.check(gate_result.get('root_child_exit_confirmed') is True,'root_child_survived_guardian_death_before_setup')
                    else:
                        signal_stop()
                        gate_result['uid_empty_while_actor_held']=self.wait_empty(binding['descriptor']['task_ruid'])
                    gate_result['facts_observed_before_release']=True
                except BaseException as error:
                    gate_result['error']=str(error);raise
            def gate_worker(point):
                try:
                    # Additive explicit test point; the native server still
                    # authenticates this QA peer as root and validates build ID.
                    base.persistence_gate_as_root.__globals__['POINTS'].add('guardian_birth_registered')
                    helper=module_path.parent/'persistence_gate.py'
                    gate_result['result']=base.persistence_gate_as_root(str(info['qa_socket']),uuid.uuid4().hex+uuid.uuid4().hex,
                        point,self.pins['qa']['build_id'],pending,str(helper))
                except BaseException as error: gate_result['error']=str(error)
            try:
                deadline=time.monotonic()+420
                while time.monotonic()<deadline:
                    try: event=messages.get(timeout=.25)
                    except queue.Empty:
                        if process.poll() is not None: break
                        continue
                    if event.get('type')=='prepared':
                        binding=event['binding'];self.task_uids.add(binding['descriptor']['task_ruid'])
                        self.expected_allocation_ids.add(binding['attempt_id'])
                        if name=='root-phase-kill':
                            gate_thread=threading.Thread(target=gate_worker,args=('guardian_birth_registered',),daemon=True);gate_thread.start()
                    if event.get('type')=='output' and 'NATIVE_READY ' in event.get('text','') and not acted:
                        acted=True;initial=self.scan(binding['descriptor']['task_ruid'])
                        self.check(initial['member_count']>=2,'detached_private_tree_not_observed')
                        if name=='cancel': signal_stop()
                        elif name=='guardian-kill':
                            entry=self.fixture_registry_snapshot()['attempts'][binding['attempt_id']]
                            self.checked_signal(entry['launch_stub'],0,info['stub'],signal.SIGKILL)
                        elif name=='daemon-kill':
                            self.root('crash-own-launchd-daemon','/bin/launchctl','kill','SIGKILL','system/'+self.label)
                            self.wait_empty(binding['descriptor']['task_ruid'])
                            self.root('restart-own-launchd-daemon','/bin/launchctl','kickstart','system/'+self.label)
                            self.check(self.label_exists(timeout=20),'restarted_daemon_not_observed')
                        elif name=='paused-daemon-authority-loss':
                            entry=self.fixture_registry_snapshot()['attempts'][binding['attempt_id']]
                            authority=entry['authority']
                            self.capture_birth(authority,entry['owner_uid'],controller_runtime)
                            self.root('pause-own-launchd-daemon','/bin/launchctl','kill','SIGSTOP','system/'+self.label)
                            daemon_paused=True
                            self.checked_signal(authority,entry['owner_uid'],controller_runtime,signal.SIGKILL)
                            gate_result['uid_empty_before_daemon_resume']=self.wait_empty(binding['descriptor']['task_ruid'])
                            self.root('resume-own-launchd-daemon','/bin/launchctl','kill','SIGCONT','system/'+self.label)
                            daemon_paused=False
                        elif name=='io-stop':
                            gate_thread=threading.Thread(target=gate_worker,args=('history_journal_read',),daemon=True);gate_thread.start()
                    if event.get('type')=='result': terminal=event;break
                    if event.get('type')=='eof': break
                self.check(terminal is not None,'controller_terminal_result_missing')
                expected_success=name in ('normal','exit7','detached','silent-long')
                self.check(terminal.get('success') is expected_success,'native_case_outcome_mismatch_'+name)
                self.check(terminal.get('production_accepted') is False,'diagnostic_claimed_production')
                if gate_thread:
                    gate_thread.join(timeout=95);self.check(not gate_thread.is_alive() and 'error' not in gate_result,'held_actor_experiment_failed')
                    self.check(gate_result.get('facts_observed_before_release') is True,'held_actor_facts_missing')
                self.wait_empty(binding['descriptor']['task_ruid'])
                recovered=self.wait_terminal(info,binding)
                if name=='daemon-kill':
                    self.check(recovered.get('daemon_epoch')!=binding['descriptor'].get('daemon_epoch') and
                        recovered.get('proof_current') is False and recovered.get('cleanup_only') is True,
                        'old_daemon_epoch_receipt_was_current_success')
                process.wait(timeout=15)
                self.check(process.returncode==0,'controller_process_exit_failed')
                if name=='silent-long': self.check(time.monotonic()-begin>=125,'long_case_did_not_run_original_duration')
                self.case_results.append({'name':name,'status':'PASS_PHYSICAL_NATIVE_DIAGNOSTIC',
                    'elapsed_ms':(time.monotonic()-begin)*1000,'source_sha256':self.binaries['qa' if info['qa_socket'] else 'shipping']['source_sha256'],
                    'task_uid':binding['descriptor']['task_ruid'],'daemon_epoch':binding['descriptor'].get('daemon_epoch'),
                    'expected_success':expected_success,'production_accepted':False,'gate':gate_result,
                    'events_sha256':base.sha_file(output),'stderr_sha256':base.sha_file(stderr)})
            except BaseException as error:
                self.case_results.append({'name':name,'status':'FAIL','reason':str(error),
                    'elapsed_ms':(time.monotonic()-begin)*1000,'gate':gate_result})
                raise
            finally:
                if daemon_paused:
                    self.root('resume-own-launchd-daemon-during-cleanup','/bin/launchctl','kill','SIGCONT','system/'+self.label)
                if process.poll() is None:
                    try: signal_stop();process.wait(timeout=75)
                    except BaseException:
                        process.kill();process.wait(timeout=10)
                if gate_thread and gate_thread.is_alive(): gate_thread.join(timeout=95)
                self.active_monitor=None
        def execute(self):
            self.check(platform.machine()==args.expected_arch,'runner_architecture_mismatch')
            self.make_private_evidence()
            base.private_file(evidence/'INPUTS.json',base.canonical({'source':str(source),'files':self.input_pins,
                'controller_sha256':base.sha_file(controller),'test_signal_sha256':base.sha_file(signal_source),
                'reference_runner_sha256':base.sha_file(module_path)}))
            self.compile_uid_scan();self.compile_birth_observer()
            self.check(self.run('compile-test-signal',['/usr/bin/clang','-std=c11','-D_DARWIN_C_SOURCE','-O2','-Wall','-Wextra',
                str(signal_source),'-o',str(self.signal_binary)]).returncode==0,'test_signal_compile_failed')
            self.compile_pair(False);self.fixture_path();shipping=self.setup_fixture('shipping')
            for name in cases:
                if name not in ('io-stop','root-phase-kill'): self.case(name,shipping)
            self.cleanup()
            for name in cases:
                if name in ('io-stop','root-phase-kill'):
                    self.fixture_path();self.compile_pair(True);qa=self.setup_fixture('qa');self.case(name,qa);self.cleanup()
            self.status='PASS_PHYSICAL_NATIVE_DIAGNOSTIC_ONLY'
    runner=Runner();failure=None;diagnostics=[];raw_traceback=None
    try: runner.execute()
    except BaseException as error:
        failure=str(error);runner.status='FAIL';diagnostics.append(safe_exception(error,'execute'));raw_traceback=traceback.format_exc()
    finally:
        try: runner.cleanup()
        except BaseException as error:
            runner.status='FAIL';failure=(failure or '')+';cleanup:'+str(error)
            diagnostics.append(safe_exception(error,'cleanup'))
        if evidence.exists():
            summary={'schema':'knowledge-reliability-darwin-native-lifecycle.v1','status':runner.status,'failure':failure,
                'platform':platform.platform(),'architecture':platform.machine(),'cases':runner.case_results,
                'diagnostics':diagnostics,'raw_traceback':raw_traceback,
                'native_os_origin_qualified':False,'capability_qualified':False,'production_KVE_KVF_ACK':'NOT_RUN',
                'actual_kernel_IO_stall':'NOT_RUN; QA holds are before/after real operations',
                'binary_history':runner.binary_history,'records':runner.records,
                'source_unchanged':all(base.sha_file(source.parent/row['path'])==row['sha256'] for row in runner.input_pins)}
            (evidence/'SUMMARY.json').write_text(json.dumps(summary,indent=2)+'\n');print(json.dumps(summary,indent=2))
    return 0 if runner.status.startswith('PASS_') else 1

if __name__=='__main__':
    try: sys.exit(main())
    except SystemExit: raise
    except BaseException as error:
        # Import/constructor failures occur before Runner's finally. Emit only
        # bounded code coordinates publicly; complete traceback stays private.
        value={'diagnostics':[safe_exception(error,'bootstrap')]}
        try:
            at=sys.argv.index('--evidence');root=Path(sys.argv[at+1]).resolve()
            root.mkdir(mode=0o700,parents=True,exist_ok=True)
            with (root/'DIAGNOSTIC.json').open('x') as stream:json.dump(value,stream)
            with (root/'bootstrap.traceback.private').open('x') as stream:traceback.print_exc(file=stream)
        except BaseException: pass
        print(json.dumps(value));sys.exit(1)
