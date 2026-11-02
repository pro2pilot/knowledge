#ifndef KNOWLEDGE_LINUX_SERVICE_SEMANTIC_PROCESS_H
#define KNOWLEDGE_LINUX_SERVICE_SEMANTIC_PROCESS_H
#include "verification-linux-service-attempt-semantic.h"
#include "verification-linux-service-semantic-report.h"
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#define KV_LINUX_SEMANTIC_DEPENDENCIES 7
typedef struct kv_linux_semantic_process kv_linux_semantic_process;
typedef struct kv_linux_semantic_plan kv_linux_semantic_plan;
struct kv_linux_semantic_pins {
    unsigned char node[32],dependencies[KV_LINUX_SEMANTIC_DEPENDENCIES][32];
};
/* Diagnostic DATA only. Completion here is the exact born process and three
 * native channels, not proof about every earlier authority-UID consumer. */
struct kv_linux_semantic_observation {
    pid_t pid;
    int started,failed,cancelled,reaped,exit_code;
    int report_eof,diagnostic_eof,preparation_eof,preparation_received;
    int report_valid,plan_claimed,generation_artifact_unconfirmed;
    size_t report_bytes,diagnostic_bytes;
    uint64_t work_deadline_ns,cleanup_deadline_ns;
};
/* Pure arguments/owner validation and inert allocation precede the sole move.
 * NULL leaves *owned caller-owned. Every post-move outcome returns a retained
 * process (possibly failed); *owned becomes NULL before FD or fork effects.
 * Input comes exclusively from the genuine lease. No caller FD, identity
 * record, callback or serialized DATA constructor is accepted.
 *
 * Root runs fixed C setup in a held child behind an abortable birth barrier.
 * Parent never performs installed-path setup/copy. The child binds the whole
 * protected graph, copies/readbacks/fsyncs it into a retained private generation,
 * then drops to authority UID / worker GID, caps0/NNP and installs the separate
 * thread-only policy before executing pinned Node. No key or commands exist.
 * FD3=request, FD4=sealed private identity640, FD5=binary report, FD2=diagnostics,
 * FD7=entry survives exec, FD8=ELF closes on exec. FD6 retains the peer only
 * through the last native pre-exec check and closes before exec. Others close.
 * Unsupported policy or any setup ambiguity is refusal, never fallback.
 * Original epochs are never refreshed. Live owner polling is required;
 * stopped owner/D-state/kernel-I/O latency is not qualified. */
kv_linux_semantic_process *kv_linux_semantic_start(const struct kv_linux_semantic_pins *,
    kv_linux_attempt_semantic_lease **owned);
/* 0 active; 1 exact reap+all three actual EOFs; -1 unconfirmed observation.
 * Failure remains owned and must continue draining, including failed starts. */
int kv_linux_semantic_poll(kv_linux_semantic_process *);
int kv_linux_semantic_cancel(kv_linux_semantic_process *);
int kv_linux_semantic_observe(const kv_linux_semantic_process *,struct kv_linux_semantic_observation *);
/* EBUSY until exact child reap and report/diagnostic/preparation EOF. Close
 * inputs before releasing the lease; inherited calls leave *owned untouched.
 * No artifact removal or durable journal closure is inferred. */
int kv_linux_semantic_close(kv_linux_semantic_process **owned);
/* Pure readiness precedes one-shot burn, which precedes all dynamic checks.
 * Exact6400 validation + actual exit0/drain + final fresh genuine lease/clock
 * are required. The borrowed plan lives until process close. It is semantic
 * preparation only, not a key, command permit, execution or terminal receipt. */
int kv_linux_semantic_claim_plan(kv_linux_semantic_process *,const kv_linux_semantic_plan **out);
int kv_linux_semantic_plan_observe(const kv_linux_semantic_plan *,struct kv_linux_semantic_timed_report_data *out);
int kv_linux_semantic_plan_current(const kv_linux_semantic_plan *);
extern const char *const kv_linux_semantic_dependency_paths[KV_LINUX_SEMANTIC_DEPENDENCIES];
#endif
