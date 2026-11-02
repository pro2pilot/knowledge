#ifndef KNOWLEDGE_LINUX_SERVICE_SEMANTIC_PLAN_INPUT_H
#define KNOWLEDGE_LINUX_SERVICE_SEMANTIC_PLAN_INPUT_H
#include "verification-linux-service-semantic-plan.h"
#include <stdint.h>
#include <sys/types.h>

/* Private fixed-native-launcher handoff, never a caller DATA constructor.
 * The completed parser pidfd remains the original held kernel birth object;
 * fdinfo may now show Pid=-1. parser_pid is historical metadata only and MUST
 * NOT be reopened or used as a numeric signal target after reap. Source root
 * and request body FDs stay in the retained original provider/process. */
struct kv_linux_semantic_plan_input {
    int peer_pidfd,clock_namespace_fd,parser_pidfd;
    pid_t parser_pid;
    uint64_t semantic_sequence,exclusive_sequence,native_revision;
    unsigned char pending_record[KV_LINUX_ATTEMPT_PENDING_BYTES];
    unsigned char semantic_report[KV_LINUX_SEMANTIC_REPORT_BYTES];
};

/* Only a genuine moved owned plan lease can supply this input. Caller sets
 * all three output FDs to -1. Pure owner/output validation precedes a permanent
 * handoff burn; current checks and all three CLOEXEC dup operations follow it.
 * All results are staged locally and publication follows a final fresh native
 * role/current check. Any failure leaves the WHOLE output unchanged, closes
 * only staged duplicate FDs and never permits retry after resource restoration.
 * Input is derived from private actual pending640/report6400/birth/sequence;
 * no plan_observe DATA or expected record is accepted back into this API.
 * The supported consumer retains the moved lease through actual native drain;
 * merely holding duplicated FDs cannot retain current or role authority. */
int kv_linux_semantic_plan_lease_claim_launch_input(kv_linux_semantic_plan_lease *,
    struct kv_linux_semantic_plan_input *out_fds_minus_one);

struct kv_linux_key_process;struct kv_linux_execution;struct kv_linux_owned_worker_result;
struct kv_linux_cleanup_phase;struct kv_linux_cleanup_phase_seed;
struct kv_linux_service_input_guard;struct kv_linux_source_custody;
/* Fixed genuine retained-chain phase bridges. All NEW *_matches are pure
 * Boolean1/0; mutations/accessors return0/-1. No caller seed is authority. */
int kv_linux_semantic_plan_lease_phase_bind(kv_linux_semantic_plan_lease *,struct kv_linux_key_process *,
    struct kv_linux_execution *,struct kv_linux_owned_worker_result *,struct kv_linux_cleanup_phase *);
int kv_linux_semantic_plan_lease_phase_seed(kv_linux_semantic_plan_lease *,struct kv_linux_key_process *,
    struct kv_linux_execution *,struct kv_linux_owned_worker_result *,struct kv_linux_cleanup_phase *,struct kv_linux_cleanup_phase_seed *);
int kv_linux_semantic_plan_lease_phase_guard_matches(const kv_linux_semantic_plan_lease *,const struct kv_linux_key_process *,
    const struct kv_linux_execution *,const struct kv_linux_owned_worker_result *,const struct kv_linux_cleanup_phase *,const struct kv_linux_service_input_guard *);
int kv_linux_semantic_plan_lease_phase_custody_matches(const kv_linux_semantic_plan_lease *,const struct kv_linux_key_process *,
    const struct kv_linux_execution *,const struct kv_linux_owned_worker_result *,const struct kv_linux_cleanup_phase *,const struct kv_linux_source_custody *);
int kv_linux_semantic_plan_lease_phase_detach(kv_linux_semantic_plan_lease *,struct kv_linux_key_process *,
    struct kv_linux_execution *,struct kv_linux_owned_worker_result *,struct kv_linux_cleanup_phase *);
int kv_linux_semantic_plan_lease_phase_revoke_guard(kv_linux_semantic_plan_lease *,struct kv_linux_key_process *,
    struct kv_linux_execution *,struct kv_linux_owned_worker_result *,struct kv_linux_cleanup_phase *);
int kv_linux_semantic_plan_lease_phase_cancel_poll(kv_linux_semantic_plan_lease *,struct kv_linux_key_process *,
    struct kv_linux_execution *,struct kv_linux_owned_worker_result *,struct kv_linux_cleanup_phase *);
int kv_linux_semantic_plan_lease_phase_retire(kv_linux_semantic_plan_lease *,struct kv_linux_key_process *,
    struct kv_linux_execution *,struct kv_linux_owned_worker_result *,struct kv_linux_cleanup_phase *);
#endif
