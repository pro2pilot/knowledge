#ifndef KNOWLEDGE_LINUX_SERVICE_CLEANUP_PHASE_INPUT_H
#define KNOWLEDGE_LINUX_SERVICE_CLEANUP_PHASE_INPUT_H
#include "verification-linux-service-cleanup-phase.h"
#include "verification-linux-service-phase-wire.h"
#include <sys/types.h>

typedef struct kv_linux_execution kv_linux_execution;
typedef struct kv_linux_key_process kv_linux_key_process;
typedef struct kv_linux_service_input_guard kv_linux_service_input_guard;
typedef struct kv_linux_source_custody kv_linux_source_custody;
/* Finite private facts read from actual native component records. No function
 * accepts a caller vote/boolean as a state transition or drain constructor. */
enum kv_linux_cleanup_fact {KV_CLEANUP_BOUND=1,KV_CLEANUP_PREPARED=2,KV_CLEANUP_ACKED=3,
    KV_CLEANUP_EXPECTED_NATIVE_DRAINED=4,KV_CLEANUP_NATIVE_RESOURCES_RETIRED=5};
enum kv_linux_cleanup_direction {KV_CLEANUP_TO_PARTICIPANT=1,KV_CLEANUP_FROM_PARTICIPANT=2};
#if defined(KNOWLEDGE_LINUX_CLEANUP_PHASE_TEST_HOOK)
/* Fixed compile-time QA seams only. Absent from production codegen/API. */
int knowledge_linux_cleanup_phase_test_hook(const char *,kv_linux_cleanup_phase *,kv_linux_owned_worker_result *,unsigned);
#define KV_CLEANUP_HOOK(stage,phase,result,role) knowledge_linux_cleanup_phase_test_hook(stage,phase,result,role)
#else
#define KV_CLEANUP_HOOK(stage,phase,result,role) 0
#endif
struct kv_linux_cleanup_participant {
    uint32_t role;
    pid_t pid;
    uid_t uid;
    gid_t gid;
    unsigned char participant_nonce[32]; /* Original actual birth context. */
    unsigned char startup_context_sha256[32];
};
/* PRIVATE OUTPUT ONLY, collected once through the actual moved result chain.
 * No public start/claim accepts this DATA or these opaque pointers. No raw FD,
 * arbitrary validator callback, new clock or caller phase flag is exported. */
struct kv_linux_cleanup_phase_seed {
    kv_linux_execution *execution;
    kv_linux_key_process *key;
    kv_linux_service_input_guard *guard;
    kv_linux_source_custody *custody;
    unsigned char pending_record[640],boot_id[16],native_result_sha256[32];
    uint64_t work_deadline_ns,cleanup_deadline_ns,time_namespace_dev,time_namespace_ino;
    uint64_t semantic_sequence,exclusive_sequence,native_revision;
    struct kv_linux_cleanup_participant participants[3]; /* SOURCE, KEY, WORKER */
};

/* ALL NEW *_matches below return Boolean 1 match / 0 refusal, purely.
 * Existing legacy execution_start_matches/worker_drain_matches remain 0/-1.
 * Mutations/accessors/current/binding return 0 success / -1 refusal. Per-role
 * poll returns 0 for no error, including pending; state_matches gives progress.
 * Pure phase counterparts inspect genuine retained ownership, never current,
 * protocol I/O, supplied callbacks or recursive component matching. */
int kv_linux_cleanup_phase_result_matches(const kv_linux_cleanup_phase *,const kv_linux_owned_worker_result *);
int kv_linux_cleanup_phase_key_matches(const kv_linux_cleanup_phase *,const kv_linux_key_process *);
int kv_linux_cleanup_phase_guard_matches(const kv_linux_cleanup_phase *,const kv_linux_service_input_guard *);
int kv_linux_cleanup_phase_custody_matches(const kv_linux_cleanup_phase *,const kv_linux_source_custody *);
int kv_linux_execution_result_phase_matches(const kv_linux_execution *,const kv_linux_key_process *,
    const kv_linux_owned_worker_result *,const kv_linux_cleanup_phase *);
/* Actual private chain comparison permits initial pure registration before the
 * seed is collected. They may use the direct result counterpart, but never
 * call the same role counterpart back or recurse through current. */
int kv_linux_owned_worker_result_phase_key_matches(const kv_linux_owned_worker_result *,const kv_linux_cleanup_phase *,const kv_linux_key_process *);
int kv_linux_owned_worker_result_phase_guard_matches(const kv_linux_owned_worker_result *,const kv_linux_cleanup_phase *,const kv_linux_service_input_guard *);
int kv_linux_owned_worker_result_phase_custody_matches(const kv_linux_owned_worker_result *,const kv_linux_cleanup_phase *,const kv_linux_source_custody *);

/* Uses the actual admission guard/endpoint, original epoch and native revision.
 * Never polls any component or calls result/key/provider legacy WORK current.
 * Initial source validation happens before the first PREPARE, then all cross-
 * owner checks use this source-free path, including partial preparation. */
int kv_linux_cleanup_phase_guard(kv_linux_cleanup_phase *);
int kv_linux_cleanup_phase_component_current(kv_linux_cleanup_phase *,kv_linux_owned_worker_result *,enum kv_linux_phase_role);
/* Negative only: invalidate phase, then same guard revision before any signal.
 * No component poll/cancel, source I/O, recursion or successful bind required. */
int kv_linux_cleanup_phase_revoke(kv_linux_cleanup_phase *,kv_linux_owned_worker_result *);
/* Pure finite DATA accessor, only for the same registered result and role.
 * Direction derives actual sender/receiver from the frozen native roster. */
int kv_linux_cleanup_phase_binding(const kv_linux_cleanup_phase *,const kv_linux_owned_worker_result *,
    enum kv_linux_phase_role,enum kv_linux_cleanup_direction,struct kv_linux_phase_binding *out);
enum kv_linux_cleanup_state kv_linux_cleanup_phase_state(const kv_linux_cleanup_phase *,const kv_linux_owned_worker_result *);

int kv_linux_owned_worker_result_phase_bind(kv_linux_owned_worker_result *,kv_linux_cleanup_phase *);
int kv_linux_owned_worker_result_phase_seed(kv_linux_owned_worker_result *,kv_linux_cleanup_phase *,struct kv_linux_cleanup_phase_seed *out);
int kv_linux_worker_phase_prepare(kv_linux_owned_worker_result *,kv_linux_cleanup_phase *);
int kv_linux_worker_phase_poll(kv_linux_owned_worker_result *,kv_linux_cleanup_phase *);
int kv_linux_worker_phase_detach(kv_linux_owned_worker_result *,kv_linux_cleanup_phase *);
int kv_linux_worker_phase_retire(kv_linux_owned_worker_result *,kv_linux_cleanup_phase *);
int kv_linux_worker_phase_state_matches(const kv_linux_owned_worker_result *,const kv_linux_cleanup_phase *,enum kv_linux_cleanup_fact);
int kv_linux_owned_worker_result_phase_revoke_guard(kv_linux_owned_worker_result *,kv_linux_cleanup_phase *);

/* Root key owner signatures remain four opaque inputs, plus output for seed.
 * Seed walks the same actual key/plan/provider chain; no observations construct
 * a participant. Retire closes confirmed native resources, not allocations. */
int kv_linux_key_phase_bind(kv_linux_key_process *,kv_linux_execution *,kv_linux_owned_worker_result *,kv_linux_cleanup_phase *);
int kv_linux_key_phase_seed(kv_linux_key_process *,kv_linux_execution *,kv_linux_owned_worker_result *,kv_linux_cleanup_phase *,struct kv_linux_cleanup_phase_seed *out);
int kv_linux_key_phase_prepare(kv_linux_key_process *,kv_linux_execution *,kv_linux_owned_worker_result *,kv_linux_cleanup_phase *);
int kv_linux_key_phase_poll(kv_linux_key_process *,kv_linux_execution *,kv_linux_owned_worker_result *,kv_linux_cleanup_phase *);
int kv_linux_key_phase_detach(kv_linux_key_process *,kv_linux_execution *,kv_linux_owned_worker_result *,kv_linux_cleanup_phase *);
int kv_linux_key_phase_retire(kv_linux_key_process *,kv_linux_execution *,kv_linux_owned_worker_result *,kv_linux_cleanup_phase *);
int kv_linux_key_phase_revoke_guard(kv_linux_key_process *,kv_linux_execution *,kv_linux_owned_worker_result *,kv_linux_cleanup_phase *);
int kv_linux_key_phase_state_matches(const kv_linux_key_process *,const kv_linux_execution *,const kv_linux_owned_worker_result *,const kv_linux_cleanup_phase *,enum kv_linux_cleanup_fact);
int kv_linux_key_phase_guard_matches(const kv_linux_key_process *,const kv_linux_execution *,const kv_linux_owned_worker_result *,const kv_linux_cleanup_phase *,const kv_linux_service_input_guard *);
int kv_linux_key_phase_custody_matches(const kv_linux_key_process *,const kv_linux_execution *,const kv_linux_owned_worker_result *,const kv_linux_cleanup_phase *,const kv_linux_source_custody *);

int kv_linux_source_custody_phase_bind(kv_linux_source_custody *,kv_linux_owned_worker_result *,kv_linux_cleanup_phase *);
int kv_linux_source_custody_phase_seed(kv_linux_source_custody *,kv_linux_owned_worker_result *,kv_linux_cleanup_phase *,struct kv_linux_cleanup_participant *out);
int kv_linux_source_custody_phase_prepare(kv_linux_source_custody *,kv_linux_owned_worker_result *,kv_linux_cleanup_phase *);
int kv_linux_source_custody_phase_poll(kv_linux_source_custody *,kv_linux_owned_worker_result *,kv_linux_cleanup_phase *);
int kv_linux_source_custody_phase_detach(kv_linux_source_custody *,kv_linux_owned_worker_result *,kv_linux_cleanup_phase *);
int kv_linux_source_custody_phase_retire(kv_linux_source_custody *,kv_linux_owned_worker_result *,kv_linux_cleanup_phase *);
int kv_linux_source_custody_phase_state_matches(const kv_linux_source_custody *,const kv_linux_owned_worker_result *,const kv_linux_cleanup_phase *,enum kv_linux_cleanup_fact);

int kv_linux_service_input_phase_bind(kv_linux_service_input_guard *,kv_linux_owned_worker_result *,kv_linux_cleanup_phase *);
int kv_linux_service_input_phase_seed(kv_linux_service_input_guard *,kv_linux_owned_worker_result *,kv_linux_cleanup_phase *,struct kv_linux_cleanup_phase_seed *out);
int kv_linux_service_input_phase_prepare(kv_linux_service_input_guard *,kv_linux_owned_worker_result *,kv_linux_cleanup_phase *);
int kv_linux_service_input_phase_commit(kv_linux_service_input_guard *,kv_linux_owned_worker_result *,kv_linux_cleanup_phase *);
int kv_linux_service_input_phase_current(kv_linux_service_input_guard *,kv_linux_owned_worker_result *,kv_linux_cleanup_phase *);
int kv_linux_service_input_phase_cancel(kv_linux_service_input_guard *,kv_linux_owned_worker_result *,kv_linux_cleanup_phase *);
int kv_linux_service_input_phase_detach(kv_linux_service_input_guard *,kv_linux_owned_worker_result *,kv_linux_cleanup_phase *);
#endif
