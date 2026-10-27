#!/usr/bin/env python3
"""Modeled receipt rejection tests; never claims physical macOS execution."""
import ast, copy, importlib.util, json, os, tempfile, unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('macos_summary_under_test', HERE/'macos-writable-summary.py')
m = importlib.util.module_from_spec(spec);spec.loader.exec_module(m)


class ProjectionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='macos-summary-', dir=os.environ.get('TMPDIR'))
        self.addCleanup(self.tmp.cleanup);self.base = Path(self.tmp.name)
        self.source = self.base/'.knowledge';self.private = self.base/'private';self.private.mkdir()
        for name in ('tools/lib/verification-darwin-broker.m', 'tools/lib/verification-darwin-stub.c', 'tools/native/lock-publication.c', 'tools/example.js'):
            file = self.source/name;file.parent.mkdir(parents=True, exist_ok=True);file.write_bytes(name.encode())
        (self.source/'config.yaml').write_text('updates:\n  enabled: true\n')
        (self.source/'tools/example.js').write_text("throw fail('command_exact_static_failure');\n")
        self.source_rows = [{'path': file.relative_to(self.source.parent).as_posix(), 'bytes': file.stat().st_size,
            'sha256': m.sha(file.read_bytes()), 'executable': False} for file in sorted(self.source.rglob('*')) if file.is_file()]
        self.inputs = {'files': self.source_rows, 'writable_assets': {name: m.sha((HERE/name).read_bytes()) for name in m.ASSETS},
            'controller_sha256': m.sha((HERE/'darwin-production-controller.js').read_bytes()),
            'reference_runner_sha256': m.sha((HERE.parent/'reference/qa/darwin-pipeline4/run_pipeline4.py').read_bytes()),
            'lifecycle_sha256': m.sha((HERE/'darwin-production-lifecycle.py').read_bytes())}
        addon = {'schema_version': 'knowledge-lock-native-binary.v1', 'platform': 'darwin', 'architecture': 'x64',
            'source_sha256': m.sha((self.source/'tools/native/lock-publication.c').read_bytes()),
            'binary_sha256': m.sha(b'addon'), 'binary_bytes': 5, 'binary': 'lock-publication.node', 'napi_version': 8}
        stage = self.private/'macos-package-stage'
        for row in self.source_rows:
            name = row['path'].removeprefix('.knowledge/');file = stage/name;file.parent.mkdir(parents=True, exist_ok=True);file.write_bytes((self.source/name).read_bytes())
        (stage/'tools/macos-qa-step.js').write_text(m.fixture.LEAF)
        native = stage/'tools/lib/native/darwin-x64';native.mkdir(parents=True)
        (native/'lock-publication.node').write_bytes(b'addon');(native/'lock-publication.manifest.json').write_bytes(m.canonical(addon))
        members = [{'path': file.relative_to(stage).as_posix(), 'bytes': file.stat().st_size, 'sha256': m.sha(file.read_bytes())}
            for file in sorted(stage.rglob('*')) if file.is_file()]
        (self.private/'macos-workspace-provision').write_bytes(b'provision')
        self.special = {'leaf_sha256': m.sha(m.fixture.LEAF.encode()), 'caller_sha256': m.sha(m.fixture.CALLER.encode()),
            'provision_source_sha256': m.sha((HERE/'macos-workspace-provision.c').read_bytes()), 'provision_binary_sha256': m.sha(b'provision'),
            'protected_package_sha256': m.sha(m.canonical(members)), 'protected_package_members': members,
            'package_derivation': 'exact runtime copy plus fixed QA leaf and compiled source-bound addon'}
        code = next(ast.literal_eval(node.value) for node in ast.walk(ast.parse((HERE/'macos-writable-lifecycle.py').read_text()))
            if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == 'batch_code' for t in node.targets))
        (self.private/'macos-exact-signal-batch.c').write_text(code);(self.private/'macos-exact-signal-batch').write_bytes(b'batch')
        self.write('MACOS_SIGNAL_BATCH_INPUTS.json', {'source_sha256': m.sha(code.encode()), 'binary_sha256': m.sha(b'batch'),
            'included_exact_signal_source_sha256': m.sha((HERE/'darwin-test-signal.c').read_bytes())})
        rows = []
        for name in m.CASES:
            observation = {key: True for key in ('exact_actor_exits', 'independent_uid_zero', 'typed_native_closure', 'automatic_native_cleanup',
                'outside_canary_unchanged', 'scheduling_pause_not_kernel_io', 'actual_state_writer_fifo_fd_observed', 'both_guardians_and_controller_exact_kill_delivered')}
            observation.update(acceptance_after_cancel=False, external_recovery_requested=False, private_allocation_count=2 if name in (m.CASES[0],m.CASES[-1]) else 1)
            terminal = {'ok': True, 'value': {'status': 'pass', 'ownership': {'status': 'completed'}}};rc = 0
            if name == m.CASES[0]:
                a = {key: True for key in ('detached_tree_ready', 'private_uid_outside_write_denied', 'metadata_change_denied', 'owner_uid_escalation_denied', 'nonpinned_exec_denied')};a['uid'] = 1000000001
                terminal['value'] = {'first': {'success': True, 'parsed': a, 'ownership': {'status': 'completed'}},
                    'second': {'success': True, 'parsed': {'uid':1000000002, 'previous_uid':1000000001, 'writable_continuity':True}, 'ownership': {'status':'completed'}}, 'owner_write_continuity':True}
            elif name in ('cancel', 'state_writer_fifo_read_cancel'):
                terminal = {'ok':False, 'code':'command_cancelled', 'cleanup':{'status':'completed'}, 'recovery_required':False};rc = 2
            elif 'death' in name: terminal = None;rc = -9
            rows.append({'name':name, 'status':'PASS_PHYSICAL_MACOS_WRITABLE', 'observations':observation, 'terminal':terminal, 'controller_exit_code':rc, 'elapsed_ms':1000})
        (self.private/'broker-shipping-01').write_bytes(b'broker');(self.private/'stub-shipping-01').write_bytes(b'stub')
        history = {'kind':'shipping', 'qa_io_enabled':False, 'source_sha256':m.sha((self.source/'tools/lib/verification-darwin-broker.m').read_bytes()),
            'stub_source_sha256':m.sha((self.source/'tools/lib/verification-darwin-stub.c').read_bytes()), 'broker_sha256':m.sha(b'broker'), 'stub_sha256':m.sha(b'stub')}
        self.raw = {'status':'PASS_PHYSICAL_MACOS_WRITABLE', 'case_set':'writable', 'architecture':'x86_64', 'source_unchanged':True,
            'cleanup_confirmed':True, 'cases':rows, 'binary_history':[history], 'native_addon':addon,
            'installed_bindings':[{'role':name, 'source_sha256':m.sha(name.encode()), 'installed_sha256':m.sha(name.encode())} for name in ('broker','stub','node')]}
        bindings=[];closures=[]
        for i in (1,2):
            descriptor={'attempt_id':str(i)*64,'source_sha256':history['source_sha256'],'stub_source_sha256':history['stub_source_sha256'],
                'schema':'knowledge-macos-writable-descriptor.v1','mode':'admin_writable_workspace.v1','stub_wire_version':'KVS3','task_ruid':1000000000+i}
            binding={'attempt_id':descriptor['attempt_id'],'descriptor':descriptor,'descriptor_sha256':m.sha(m.canonical(descriptor))};bindings.append(binding)
            closure={key:True for key in ('ok','cleanup_only','capability_qualified','cleanup_observation_current','registry_healthy',
                'allocation_tuple_verified_current','kernel_membership_zero','admission_closed','spawn_exclusion_acquired','spawn_intents_resolved',
                'guardian_exit_confirmed','root_child_exit_confirmed','registered_authority_exited','native_scope_closed','clock_healthy')}
            closure.update({key:False for key in ('proof_current','observation_cached','qualification_mode','qa_persistence_gate','active_attempt')})
            closure.update(schema='knowledge-darwin-scope-observation.v1',status='completed',state='closed',attempt_id=descriptor['attempt_id'],
                descriptor_sha256=binding['descriptor_sha256'],observation_nonce='9'*64,source_sha256=history['source_sha256'],
                stub_source_sha256=history['stub_source_sha256'],binary_sha256=history['broker_sha256'],stub_binary_sha256=history['stub_sha256'])
            closures.append(closure)
        scopes=[{'schema_version':'knowledge-command-scope.v1','backend':'macos_uid_guardian','binding':binding} for binding in bindings]
        old_lock='12345678-1234-1234-1234-123456789012';new_lock='22345678-1234-1234-1234-123456789012'
        scope_text=m.canonical(scopes[0]).decode();owner_text=m.canonical({'schema_version':'knowledge-lock-owner.v3','lock_id':old_lock,'pid':123,
            'publication':'atomic-directory-noreplace.v1','kernel_lease':{'method':'owner-inode-lease.v1','owner_ino':'1','directory_ino':'2'},
            'execution_scope':{'schema_version':'knowledge-command-scope-binding.v1','backend':'macos_uid_guardian','sha256':m.sha(scope_text.encode())}}).decode()
        starts=[{'schema_version':'knowledge-team-flow-start.v2','run_id':'TFR-'+str(i)*32,'repo_id':'repo','workspace_id':'work','state_root':'state',
            'flow':'doctor','retry_of':None,'content_sha256':str(i)*64} for i in (1,2)]
        out={**starts[1],'checks_status':'failed','overall_status':'failed','team_release':{'status':'released'},'steps_total':8,
            'steps':[{'command':name} for name in m.DOCTOR_STEPS]}
        out.update({key:{'status':'completed'} for key in ('ownership','command_cleanup','command_authority_cleanup')})
        report={'value':out,'scope':scopes[1],'cleanup':{'status':'completed'}}
        final={**starts[1],'schema_version':'knowledge-team-flow-finalization.v2','start_sha256':starts[1]['content_sha256'],
            'release':{'status':'released'},'final_status':'failed','checks_status':'failed'}
        events=[{'type':'lock_acquired','lock':'flow','lock_id':name} for name in (old_lock,new_lock)]
        events.append({'type':'lock_released','lock':'flow','lock_id':new_lock,'released':True})
        self.team_proof={'old_owner_text':owner_text,'old_scope_text':scope_text,'quarantined_owner_text':owner_text,'quarantined_scope_text':scope_text,
            'old_start':starts[0],'new_start':starts[1],'new_final':final,'old_final_exists':False,'lock_absent':True,
            'team_events':events,'native_closures':closures,'retry_report':report}
        team=rows[-1];team.update(initial_controller_exit_code=-9,controller_exit_code=0,terminal={'type':'result','ok':True,'value':out,'cleanup':report['cleanup']},
            quality_status='failed',overall_status='failed')
        team['observations'].update({key:True for key in m.TEAM_FACTS});team['observations'].update(manual_owner_repair=False,fresh_team_steps_executed=8)
        self.write_team_proof()
        (self.private/'macos-team-recovery-caller.cjs').write_text(m.fixture.TEAM_CALLER)
        self.write('TEAM_RECOVERY_INPUTS.json',{'team_caller_sha256':m.sha(m.fixture.TEAM_CALLER.encode()),'updates_disabled':True,
            'expected_shipping_doctor_steps':8,'original_config_sha256':m.sha((self.source/'config.yaml').read_bytes()),
            'configured_config_sha256':m.sha(b'updates:\n  enabled: false\n')})

    def write(self, name, value): (self.private/name).write_bytes(m.canonical(value))
    def write_team_proof(self):
        self.write('TEAM_RECOVERY_PROOF.private.json',self.team_proof)
        self.raw['cases'][-1]['team_recovery_proof_sha256']=m.sha(m.canonical(self.team_proof))
    def project(self):
        self.write('SUMMARY.json',self.raw);self.write('INPUTS.json',self.inputs);self.write('MACOS_WRITABLE_INPUTS.json',self.special)
        return m.build(self.private,self.source,0,'x86_64')
    def test_positive_exact_derived_inventory(self):
        self.assertEqual(self.project()['status'],'PASS_PHYSICAL_MACOS_WRITABLE')
    def test_every_missing_or_nonboolean_cleanup_fact_rejected(self):
        for index in range(len(m.CASES)):
            for key in ('exact_actor_exits','independent_uid_zero','typed_native_closure','automatic_native_cleanup','outside_canary_unchanged','external_recovery_requested','acceptance_after_cancel'):
                for bad in (None, 1):
                    with self.subTest(case=index,key=key,bad=bad):
                        row=copy.deepcopy(self.raw['cases'][index]);row['observations'][key]=bad
                        self.assertEqual(m.case_projection(row)['status'],'FAIL_OR_INCOMPLETE')
    def test_missing_case_duplicate_order_and_unknown_case_rejected(self):
        original=copy.deepcopy(self.raw['cases'])
        for bad in (original[:-1],original+[original[0]],list(reversed(original)),[dict(original[0],name='/private/secret')]+original[1:]):
            self.raw['cases']=bad;self.assertEqual(self.project()['status'],'FAIL_OR_INCOMPLETE')
    def test_cancel_recovery_fifo_and_three_kill_facts_required(self):
        for index,key,container in ((2,'recovery_required','terminal'),(5,'actual_state_writer_fifo_fd_observed','observations'),(4,'both_guardians_and_controller_exact_kill_delivered','observations')):
            row=copy.deepcopy(self.raw['cases'][index]);row[container].pop(key)
            self.assertEqual(m.case_projection(row)['status'],'FAIL_OR_INCOMPLETE')
    def test_changed_source_fixture_native_and_package_bindings_rejected(self):
        mutations=[(self.inputs,'lifecycle_sha256'),(self.special,'leaf_sha256'),(self.special,'protected_package_sha256'),
            (self.special,'provision_binary_sha256'),(self.raw['binary_history'][0],'source_sha256'),(self.raw['native_addon'],'binary_sha256'),
            (self.raw['installed_bindings'][0],'installed_sha256')]
        for value,key in mutations:
            old=value[key];value[key]='0'*64
            with self.subTest(key=key): self.assertEqual(self.project()['status'],'FAIL_OR_INCOMPLETE')
            value[key]=old
    def test_derived_inventory_cannot_omit_add_or_escape_even_with_rehashed_list(self):
        old=copy.deepcopy(self.special)
        for operation in ('omit','add','escape','duplicate'):
            self.special=copy.deepcopy(old);members=self.special['protected_package_members']
            if operation=='omit': members.pop()
            elif operation=='add': members.append({'path':'tools/extra.js','bytes':1,'sha256':'1'*64})
            elif operation=='escape': members[0]['path']='../outside'
            else: members.append(members[0])
            self.special['protected_package_sha256']=m.sha(m.canonical(members))
            self.assertEqual(self.project()['status'],'FAIL_OR_INCOMPLETE')
    def test_actual_package_and_batch_bytes_are_read_back(self):
        for name in ('macos-package-stage/tools/macos-qa-step.js','macos-exact-signal-batch.c','macos-exact-signal-batch'):
            file=self.private/name;old=file.read_bytes();file.write_bytes(old+b'changed')
            self.assertEqual(self.project()['status'],'FAIL_OR_INCOMPLETE');file.write_bytes(old)
    def test_raw_paths_identities_and_capabilities_do_not_enter_public_projection(self):
        secret='command_'+('a1b2c3d4'*8);self.raw['cases'][0]['terminal']['code']=secret
        self.raw['cases'][0]['secret']='/Users/private/private-token-123';self.raw['failure']='/Users/private/private-token-123 '+secret
        self.raw['records']=[{'name':'001-compile-shipping-broker'}]
        (self.private/'001-compile-shipping-broker.stderr.raw').write_text('/Users/private/private-token-123 '+secret)
        output=json.dumps(self.project())
        self.assertNotIn(secret,output);self.assertNotIn('/Users/private',output);self.assertNotIn('private-token-123',output)
    def test_python_bool_does_not_count_as_success_exit_code(self):
        row=copy.deepcopy(self.raw['cases'][0]);row['controller_exit_code']=False
        self.assertEqual(m.case_projection(row)['status'],'FAIL_OR_INCOMPLETE')
    def test_actual_inputs_filename_is_required(self):
        self.project();(self.private/'INPUTS.json').rename(self.private/'WRONG_INPUTS.json')
        self.assertEqual(m.build(self.private,self.source,0,'x86_64')['status'],'FAIL_OR_INCOMPLETE')
    def test_team_every_claim_is_required_and_not_boolean_like(self):
        for key in (*m.TEAM_FACTS,'manual_owner_repair','fresh_team_steps_executed'):
            for value in (None,1):
                row=copy.deepcopy(self.raw['cases'][-1]);row['observations'][key]=value
                self.assertEqual(m.case_projection(row)['status'],'FAIL_OR_INCOMPLETE',key)
    def test_team_actual_proof_is_required_despite_all_true_claims(self):
        proof=copy.deepcopy(self.team_proof)
        changes=[lambda p:p.pop('old_owner_text'),lambda p:p.update(quarantined_scope_text='{}'),
            lambda p:p.update(old_final_exists=True),lambda p:p.update(lock_absent=False),
            lambda p:p['new_start'].update(run_id=p['old_start']['run_id']),
            lambda p:p['new_final'].update(start_sha256='0'*64),lambda p:p['new_final']['release'].update(status='failed'),
            lambda p:p['team_events'].pop(),lambda p:p['team_events'][1].update(lock_id=p['team_events'][0]['lock_id']),
            lambda p:p['native_closures'][0].update(kernel_membership_zero=False),lambda p:p['native_closures'][1].update(observation_cached=True),
            lambda p:p['native_closures'][0].update(source_sha256='0'*64),lambda p:p['retry_report']['value']['steps'].pop(),
            lambda p:p['retry_report']['cleanup'].update(status='unconfirmed')]
        for change in changes:
            self.team_proof=copy.deepcopy(proof);change(self.team_proof);self.write_team_proof()
            self.assertEqual(self.project()['status'],'FAIL_OR_INCOMPLETE')
    def test_team_quality_failure_is_not_confused_with_ownership_failure(self):
        result=self.project();self.assertEqual(result['status'],'PASS_PHYSICAL_MACOS_WRITABLE')
        self.assertEqual(result['cases'][-1]['quality_status'],'failed')
        self.assertTrue(result['cases'][-1]['facts']['exact_team_recovery_proof_verified'])
    def test_actual_native_binary_readback_and_static_error_catalog(self):
        row=self.raw['cases'][0];row['terminal']['code']='command_exact_static_failure'
        row['terminal']['diagnostic']={'code':'command_exact_static_failure','native_error_code':'CAP_'+('a'*64),
            'frames':[{'file':'example.js','line':1,'column':2},{'file':'private-token.js','line':1,'column':1}]}
        result=self.project();self.assertEqual(result['cases'][0]['error_code'],'command_exact_static_failure')
        self.assertEqual(result['cases'][0]['diagnostic']['source_frames'],[{'source_file':'tools/example.js','line':1,'column':2}])
        self.assertNotIn('CAP_'+('a'*64),json.dumps(result))
        (self.private/'broker-shipping-01').write_bytes(b'changed')
        self.assertEqual(self.project()['status'],'FAIL_OR_INCOMPLETE')


if __name__=='__main__': unittest.main(verbosity=2)
