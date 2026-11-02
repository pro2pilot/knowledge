#ifndef KNOWLEDGE_LINUX_SERVICE_EXECUTION_H
#define KNOWLEDGE_LINUX_SERVICE_EXECUTION_H
#include "verification-linux-service-key-process.h"
#include <stddef.h>
#include <stdint.h>

typedef struct kv_linux_execution kv_linux_execution;
typedef struct kv_linux_owned_worker_result kv_linux_owned_worker_result;
#define KV_LINUX_WORKER_DEPENDENCIES 7
#define KV_LINUX_WORKER_OUTPUT_MAX 1048576
struct kv_linux_worker_pins {unsigned char node[32],dependencies[KV_LINUX_WORKER_DEPENDENCIES][32];};
/* Diagnostic DATA only; no native owner, current permission or drain receipt. */
struct kv_linux_execution_observation {
    int failed,cancelled,closing,keeper_started,keeper_reaped,control_eof,preparation_eof;
    int generation_artifact_unconfirmed;
    uint32_t command_count,commands_started,commands_completed;
    uint64_t work_deadline_ns,cleanup_deadline_ns;
};
struct kv_linux_worker_command_observation {
    uint32_t ordinal,type;
    int exit_code,signal,drained;
    uint64_t completed_ns,stdout_bytes,stderr_bytes;
    unsigned char command_sha256[32],stdout_sha256[32],stderr_sha256[32];
};
struct kv_linux_worker_result_observation {
    uint32_t command_count;
    unsigned char identity_sha256[32],plan_sha256[32],source_sha256[32],report_sha256[32];
    struct kv_linux_worker_command_observation commands[KV_LINUX_SEMANTIC_MAX_COMMANDS];
};
/* Original serialized root owner. Inert allocation/pure validation precedes
 * sole key move; NULL leaves *owned unchanged. All post-move outcomes retain
 * the same execution (possibly failed) until actual native drain. No caller
 * FD, observation, serialized identity or supplied validator is accepted. */
kv_linux_execution *kv_linux_execution_start(const struct kv_linux_worker_pins *,kv_linux_key_process **owned);
int kv_linux_execution_poll(kv_linux_execution *,unsigned max_wait_ms);
int kv_linux_execution_cancel(kv_linux_execution *);
int kv_linux_execution_observe(const kv_linux_execution *,struct kv_linux_execution_observation *);
/* Cancel first; EBUSY until actual workers/descendants/channels and key drain.
 * Unlink failure retains everything; no timeout, observation or PID fallback. */
int kv_linux_execution_close(kv_linux_execution **owned);
/* Pure recorded readiness precedes one-shot burn. All dynamic work follows.
 * Success moves SAME execution into the opaque result and clears *owned. */
int kv_linux_execution_claim_result(kv_linux_execution **owned,kv_linux_owned_worker_result **out_null);
int kv_linux_owned_worker_result_move(kv_linux_owned_worker_result **from,kv_linux_owned_worker_result **to_null);
int kv_linux_owned_worker_result_current(kv_linux_owned_worker_result *);
int kv_linux_owned_worker_result_observe(const kv_linux_owned_worker_result *,struct kv_linux_worker_result_observation *);
int kv_linux_owned_worker_result_close(kv_linux_owned_worker_result **owned);
#endif
