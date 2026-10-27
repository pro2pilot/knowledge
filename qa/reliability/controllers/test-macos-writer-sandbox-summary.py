#!/usr/bin/env python3
"""Modeled strict-projection tests; not physical macOS qualification."""
import copy
import unittest
from pathlib import Path
import importlib.util
HERE=Path(__file__).resolve().parent

def load(name,file):
    spec=importlib.util.spec_from_file_location(name,HERE/file);value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value
m=load('writer_summary_test','macos-writer-sandbox-summary.py')
b=load('writer_seed_fixture','test-macos-writable-summary.py')
class WriterTests(unittest.TestCase):
    def setUp(self):
        self.seed=b.ProjectionTests();self.seed.setUp();self.addCleanup(self.seed.doCleanups)
        self.p=self.seed.private;self.source=self.seed.source;self.raw=self.seed.raw;self.inputs=self.seed.inputs
        old=self.p/'macos-package-stage';stage=self.p/'macos-writer-package-stage';old.rename(stage)
        (stage/'tools/macos-qa-step.js').unlink();(stage/'tools/lib/macos-command-worker.js').write_text(m.fixture.WORKER)
        for name in ('verification-darwin-transport.h','verification-darwin-uid-history.h','verification-darwin-uid-history.m'):
            (self.source/'tools/lib'/name).write_text(name);(stage/'tools/lib'/name).write_text(name)
        self.inputs['files']=[{'path':f.relative_to(self.source.parent).as_posix(),'bytes':f.stat().st_size,'sha256':m.sha(f.read_bytes()),'executable':False} for f in sorted(self.source.rglob('*')) if f.is_file()]
        members=[{'path':f.relative_to(stage).as_posix(),'bytes':f.stat().st_size,'sha256':m.sha(f.read_bytes())} for f in sorted(stage.rglob('*')) if f.is_file()]
        (self.p/'macos-writer-provision').write_bytes(b'provision');(self.p/'macos-owner-exec-canary').write_bytes(b'canary');(self.p/'macos-writer-sandbox-caller.cjs').write_text(m.fixture.CALLER)
        self.special={'worker_sha256':m.sha(m.fixture.WORKER.encode()),'caller_sha256':m.sha(m.fixture.CALLER.encode()),'provision_source_sha256':m.sha((HERE/'macos-workspace-provision.c').read_bytes()),'provision_binary_sha256':m.sha(b'provision'),'owner_canary_source_sha256':m.sha((HERE/'macos-owner-exec-canary.c').read_bytes()),'owner_canary_binary_sha256':m.sha(b'canary'),'owner_canary_installed_uid':501,'owner_canary_installed_mode':0o4755,'owner_control':{'ruid':501,'euid':501},'package_derivation':m.fixture.DERIVATION,'protected_package_members':members,'protected_package_sha256':m.sha(m.canonical(members))}
        self.inputs['writer_sandbox_assets']={name:m.sha((HERE/name).read_bytes()) for name in m.ASSETS}
        history=self.raw['binary_history'][0]
        d={'schema':'knowledge-macos-writable-descriptor.v1','mode':'admin_writable_workspace.v1','task_ruid':1000000001,'writable_root':'/private/fixed/project',**{k:history[k] for k in ('source_sha256','stub_source_sha256')}}
        d.update(attempt_id='a'*64,host_id='12345678-1234-1234-1234-123456789abc',boot_id='12345678-1234-1234-1234-123456789abd',daemon_epoch='c'*64,installation_id='d'*64,account_policy_sha256='e'*64,account_policy_id='admin_reserved_interval_no_runtime_nss.v1',allocation_sha256='f'*64,allocation_seq='2',broker_binary_sha256=history['broker_sha256'],stub_binary_sha256=history['stub_sha256'])
        d.update({k:m.sha((self.source/'tools/lib'/name).read_bytes()) for k,name in m.SOURCE_NAMES.items()})
        binding={'attempt_id':'a'*64,'descriptor':d,'descriptor_sha256':m.sha(m.canonical(d))}
        native={'schema':'knowledge-darwin-scope-observation.v1','status':'completed','state':'closed','attempt_id':binding['attempt_id'],'descriptor_sha256':binding['descriptor_sha256'],'observation_nonce':'b'*64,**{k:d[k] for k in ('source_sha256','stub_source_sha256')}}
        native.update({k:True for k in ('ok','cleanup_only','capability_qualified','cleanup_observation_current','registry_healthy','allocation_tuple_verified_current','kernel_membership_zero','admission_closed','spawn_exclusion_acquired','spawn_intents_resolved','guardian_exit_confirmed','root_child_exit_confirmed','registered_authority_exited','native_scope_closed','clock_healthy')});native.update({k:False for k in ('proof_current','observation_cached','qualification_mode','qa_persistence_gate','active_attempt')})
        self.proof={'ok':True,'attempt_id':binding['attempt_id'],'scope':{'schema_version':'knowledge-command-scope.v1','backend':'macos_uid_guardian','binding':binding},'native_closure':native,'observation_nonce':'b'*64,'probe':{'uid':501,'pid':321,'inside_control':True,'outside_errno':'EPERM'},'births':{'writer':{'writer':{'pid':321}}},'owner_exec':{'uid':1000000001,'denied':True,'errno':'EACCES','status':None,'stdout':''},'owner_exec_command':{'status':0,'cleanup':{'status':'completed','proof':{'command_cleanup_confirmed':True,'kernel_membership_zero':True}}},'checked_directory':{'dev':'1','ino':'2'},'renamed_directory':{'dev':'1','ino':'2'},'substituted_symlink':{'target':'/private/outside'},'outside_unchanged':True,'writer_exit':{'writer_exit_observed':True,'code':0,'signal':None,'writer_sandbox':'workspace.v1','writable_root_sha256':m.sha(d['writable_root'].encode())},'authority_exit':{'writer_exit_observed':True,'signal':'SIGKILL'},'actor_observations':{k:{'state':'absent'} for k in ('authority','authority_guardian','state_writer','state_guardian','controller')},'independent_uid_scan':{'observation_valid':True,'member_count':0}}
        cap={k:d[k] for k in (*m.SOURCE_NAMES,'stub_binary_sha256','host_id','boot_id','daemon_epoch','installation_id','account_policy_sha256','account_policy_id')};cap['binary_sha256']=history['broker_sha256']
        native.update(cap);native.update(task_ruid=d['task_ruid'],allocation_seq=d['allocation_seq'],allocation_sha256=d['allocation_sha256'],observed_monotonic_ms=100,lifecycle_basis='same_boot_terminal',historical_terminal_before_new_boot=False,reboot_recovery_confirmed=False)
        self.proof.update(capability=cap,automatic_native_cleanup=True,external_recovery_requested=False)
        self.proof['births']={'writer':{'writer':{'pid':321},'guardian':{'pid':322}},'authority':{'writer':{'pid':323},'guardian':{'pid':324}}}
        actorids={'state_writer':321,'state_guardian':322,'authority':323,'authority_guardian':324,'controller':325}
        self.proof['registered_actors']={k:{'pid':v} for k,v in actorids.items()};self.proof['actor_observations']={k:{'schema':'knowledge-darwin-qa-birth.v1','pid':v,'state':'absent'} for k,v in actorids.items()}
        self.proof['independent_uid_scan'].update(uid=d['task_ruid'],errno=0,members=[])
        self.row={'name':m.fixture.CASE,'status':m.fixture.STATUS,'controller_exit_code':0,'observations':{**{k:True for k in m.FACTS},'shipping_flow_proof':False,'external_recovery_requested':False,'private_allocation_count':1}}
        self.raw.update(status=m.fixture.STATUS,case_set='writable-sandbox',cases=[self.row])
    def project(self,rc=0):
        self.row['terminal']=self.proof;self.row['proof_sha256']=m.sha(m.canonical(self.proof))
        for name,data in (('SUMMARY.json',self.raw),('INPUTS.json',self.inputs),('MACOS_WRITER_SANDBOX_INPUTS.json',self.special),('MACOS_WRITER_SANDBOX_PROOF.private.json',self.proof)):(self.p/name).write_bytes(m.canonical(data))
        return m.build(self.p,self.source,rc,'x86_64')
    def test_positive_exact_boundary_receipt(self):self.assertEqual(self.project()['status'],m.fixture.STATUS)
    def test_every_fact_is_boolean_and_required(self):
        for key in m.FACTS:
            for value in (False,1,'true',None):
                self.row['observations'][key]=value;self.assertEqual(self.project()['status'],'FAIL_OR_INCOMPLETE',key)
            self.row['observations'][key]=True
    def test_setuid_execution_and_positive_control_are_required(self):
        original=copy.deepcopy(self.proof)
        for key,value in (('uid',501),('denied',False),('stdout','credentials leaked'),('errno','ENOENT'),('status',0)):
            self.proof=copy.deepcopy(original);self.proof['owner_exec'][key]=value;self.assertEqual(self.project()['status'],'FAIL_OR_INCOMPLETE')
        self.proof=original;self.special['owner_control']['euid']=0;self.assertEqual(self.project()['status'],'FAIL_OR_INCOMPLETE')
    def test_unknown_actor_or_uid_membership_never_passes(self):
        self.proof['actor_observations']['state_writer']['state']='unknown';self.assertEqual(self.project()['status'],'FAIL_OR_INCOMPLETE')
        self.proof['actor_observations']['state_writer']['state']='absent';self.proof['independent_uid_scan']['member_count']=1;self.assertEqual(self.project()['status'],'FAIL_OR_INCOMPLETE')
    def test_native_identity_mutations_fail(self):
        original=copy.deepcopy(self.proof)
        for key in ('binary_sha256','stub_binary_sha256','source_sha256','transport_header_sha256','uid_history_header_sha256','uid_history_source_sha256','host_id','boot_id','daemon_epoch','installation_id','allocation_sha256','account_policy_sha256','task_ruid'):
            self.proof=copy.deepcopy(original);self.proof['native_closure'][key]=123 if key=='task_ruid' else '0'*64;self.assertEqual(self.project()['status'],'FAIL_OR_INCOMPLETE',key)
        self.proof=original
    def test_actual_package_and_native_bytes_are_required(self):
        (self.p/'macos-writer-package-stage/tools/lib/macos-command-worker.js').write_text('changed');self.assertEqual(self.project()['status'],'FAIL_OR_INCOMPLETE')
    def test_public_projection_has_no_raw_paths_or_process_ids(self):
        text=m.canonical(self.project()).decode();self.assertNotIn('/private/',text);self.assertNotIn('321',text);self.assertNotIn('1000000001',text);self.assertNotIn('descriptor',text)
    def test_bool_exit_and_flow_claim_cannot_pass(self):
        self.assertEqual(self.project(False)['status'],'FAIL_OR_INCOMPLETE');self.row['observations']['shipping_flow_proof']=True;self.assertEqual(self.project()['status'],'FAIL_OR_INCOMPLETE')
if __name__=='__main__':unittest.main(verbosity=2)
