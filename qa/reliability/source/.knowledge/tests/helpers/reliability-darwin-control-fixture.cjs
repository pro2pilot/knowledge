'use strict';
// Synthetic protocol payloads only. These fixtures do not qualify Darwin
// kernel containment, root-service authentication or native process death.
const wire=require('../../tools/lib/verification-darwin-session-protocol');
const clone=value=>JSON.parse(JSON.stringify(value));
function fixture() {
  const h=n=>String(n).repeat(64),id=h(4),epoch=h(3);
  const capability={source_sha256:h(1),binary_sha256:h(2),stub_source_sha256:h(5),stub_binary_sha256:h(6),
    transport_header_sha256:h(7),uid_history_header_sha256:h(8),uid_history_source_sha256:h(9),
    installation_id:h('a'),account_policy_id:'admin_reserved_interval_no_runtime_nss.v1',account_policy_sha256:h('b'),
    host_id:'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',boot_id:'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb',
    daemon_epoch:epoch,runtime_path:'/protected/node',runtime_sha256:h('c')};
  const native={...capability,schema:'knowledge-darwin-private-ruid-descriptor.v2',backend:'darwin_private_ruid',
    broker_binary_sha256:capability.binary_sha256,mode:'isolated_copy',attempt_id:id,boundary_id:id,attempt_nonce:h('d'),
    task_ruid:1000000000,task_gid:1000000000,owner_uid:501,stub_wire_version:'KVS2',guardian_protocol:'KVR2',
    capability_qualified:true,qualification_mode:false,allocation_seq:'1',allocation_sha256:h('e'),workspace_path:'/protected/work/'+id,
    allowed_runtimes:{'/protected/node':capability.runtime_sha256},work_started_monotonic_ms:100,work_budget_ms:100000,
    work_deadline_ms:100100,cleanup_budget_ms:60000};
  const scope={schema_version:'knowledge-command-scope.v1',backend:'darwin_uid_guardian',
    binding:{attempt_id:id,descriptor:native,descriptor_sha256:wire.digest(native)},
    broker_path:'/protected/broker',broker_socket:'/private/tmp/knowledge-control-fixture.sock'};
  const identity=(pid,unique,parent)=>({schema:'knowledge-darwin-process-identity.v1',host_id:native.host_id,
    boot_id:native.boot_id,owner_uid:501,birth:{pid,unique_id:unique,parent_unique_id:parent,
      start_sec:100,start_usec:10,ruid:501,pidversion:1}});
  const controller_identity=identity(1200,'101','100'),authority_identity=identity(1201,'102','101');
  const common={attempt_id:id,descriptor_sha256:scope.binding.descriptor_sha256,daemon_epoch:epoch,
    writer_generation:7,proof_current:true,capability_qualified:true};
  const proof={...common,schema:'knowledge-darwin-private-ruid-proof.v1',uid_history_tuple_verified:true,terminal_cleanup:true,
    kernel_membership_zero:true,admission_closed:true,spawn_exclusion_acquired:true,spawn_intents_resolved:true,
    guardian_exit_confirmed:true,root_child_exit_confirmed:true,cleanup_started_monotonic_ms:1000,
    cleanup_deadline_monotonic_ms:61000,observed_monotonic_ms:1100,native_cleanup_facts_confirmed:true,
    cleanup_confirmed:true,registered_authority_exited:true,cleanup_budget_exceeded:false,abort_latched:false,planned_terminal:true,
    authority_identity:authority_identity.birth,controller_identity:controller_identity.birth};
  for(const key of ['source_sha256','transport_header_sha256','installation_id','allocation_seq','allocation_sha256',
    'host_id','boot_id','account_policy_id','account_policy_sha256','task_ruid'])proof[key]=native[key];
  const terminalReply={...common,ok:true,state:'closed',cleanup_only:false,allocation_tuple_verified_current:true,
    registry_healthy:true,cleanup_budget_exceeded:false,abort_latched:false,planned_terminal:true,stop_reason:'close_requested',
    proof,proof_sha256:wire.digest(proof)};
  const observation={ok:true,schema:'knowledge-darwin-scope-observation.v1',observation_nonce:h('f'),
    attempt_id:id,descriptor_sha256:scope.binding.descriptor_sha256,host_id:native.host_id,boot_id:native.boot_id,
    daemon_epoch:epoch,capability_qualified:true,qualification_mode:false,qa_persistence_gate:false,
    proof_current:false,cleanup_only:true,observation_cached:false,status:'completed',observed_monotonic_ms:1200,
    cleanup_observation_current:true,registry_healthy:true,allocation_tuple_verified_current:true,admission_closed:true,
    spawn_exclusion_acquired:true,spawn_intents_resolved:true,kernel_membership_zero:true,guardian_exit_confirmed:true,
    root_child_exit_confirmed:true,registered_authority_exited:true,native_scope_closed:true,state:'closed',active_attempt:false,
    clock_healthy:true,lifecycle_basis:'same_boot_terminal',historical_terminal_before_new_boot:false,reboot_recovery_confirmed:false,
    authority_identity:authority_identity.birth};
  for(const key of ['source_sha256','stub_source_sha256','transport_header_sha256','uid_history_header_sha256',
    'uid_history_source_sha256','binary_sha256','stub_binary_sha256'])observation[key]=capability[key];
  for(const key of ['installation_id','allocation_seq','allocation_sha256','account_policy_id','account_policy_sha256','task_ruid'])observation[key]=native[key];
  return {capability,native,scope,controller_identity,authority_identity,terminalReply,observation};
}
module.exports={fixture,clone};
