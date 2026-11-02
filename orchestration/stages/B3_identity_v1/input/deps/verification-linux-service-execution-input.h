#ifndef KNOWLEDGE_LINUX_SERVICE_EXECUTION_INPUT_H
#define KNOWLEDGE_LINUX_SERVICE_EXECUTION_INPUT_H
#include "verification-linux-service-execution.h"
#include "verification-linux-service-result-wire.h"
typedef struct kv_linux_cleanup_phase kv_linux_cleanup_phase;
/* Private canonical DATA export from the actual still-retained result/phase.
 * No WORK/current observation or descriptor/callback factory. The caller F
 * brackets this with genuine confirmed read-access and all-native closure. */
int kv_linux_owned_worker_result_phase_transcript(const kv_linux_owned_worker_result *,const kv_linux_cleanup_phase *,
    unsigned char *out,size_t capacity,size_t *used);

/* Private fixed native composition. No public/raw FD or DATA constructor.
 * Output all four FDs=-1. Actual opaque linkage and spent opportunities bind
 * the handoff to one original-owner execution which already moved the key. */
struct kv_linux_worker_input {
    int request_fd,readonly_root_fd,peer_pidfd,clock_namespace_fd;
    unsigned char pending_record[KV_LINUX_ATTEMPT_PENDING_BYTES];
    unsigned char semantic_report[KV_LINUX_SEMANTIC_REPORT_BYTES];
    uint64_t semantic_sequence,exclusive_sequence,native_revision;
};
int kv_linux_key_claim_worker_input(kv_linux_key_process *,kv_linux_execution *,struct kv_linux_worker_input *);
int kv_linux_key_worker_link_matches(const kv_linux_key_process *,const kv_linux_semantic_plan_lease *,const kv_linux_execution *);
int kv_linux_key_worker_detach(kv_linux_key_process *,kv_linux_execution *);
/* Pure fixed validators, 0 match / -1 refusal. No caller callbacks, FD/current work or recursion.
 * Drain checks actual private execution records, never observation DATA. */
int kv_linux_execution_start_matches(const kv_linux_execution *,const kv_linux_key_process *);
int kv_linux_execution_worker_drain_matches(const kv_linux_execution *,const kv_linux_key_process *);
int kv_linux_semantic_plan_lease_claim_worker_input(kv_linux_semantic_plan_lease *,kv_linux_key_process *,kv_linux_execution *,struct kv_linux_worker_input *);
int kv_linux_semantic_plan_lease_worker_detach(kv_linux_semantic_plan_lease *,kv_linux_key_process *,kv_linux_execution *);
int kv_linux_semantic_worker_link_matches(const kv_linux_semantic_process *,const kv_linux_attempt_semantic_lease *,const kv_linux_key_process *,const kv_linux_execution *);
#endif
