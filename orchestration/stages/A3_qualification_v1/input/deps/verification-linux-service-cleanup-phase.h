#ifndef KNOWLEDGE_LINUX_SERVICE_CLEANUP_PHASE_H
#define KNOWLEDGE_LINUX_SERVICE_CLEANUP_PHASE_H
#include <stdint.h>

typedef struct kv_linux_owned_worker_result kv_linux_owned_worker_result;
typedef struct kv_linux_cleanup_phase kv_linux_cleanup_phase;
enum kv_linux_cleanup_state {
    KV_CLEANUP_MOVED_INERT=1,KV_CLEANUP_PREPARING=2,KV_CLEANUP_WORK_COMPLETE=3,
    KV_CLEANUP_COMMITTING=4,KV_CLEANUP_ACTIVE=5,KV_CLEANUP_FAILED_RETAINED=6,
    KV_CLEANUP_CANCELLING=7,KV_CLEANUP_DRAINED_RELEASEABLE=8
};
/* Diagnostic DATA only. No observed bit or snapshot recreates an owner. */
struct kv_linux_cleanup_phase_observation {
    enum kv_linux_cleanup_state state;
    int failed,cancelled;
    unsigned prepared_roles,acked_roles;
    uint64_t work_deadline_ns,cleanup_deadline_ns,phase_sequence,native_revision;
};
/* Pure original-owner validation and inert allocation precede the whole genuine
 * result move. NULL is pre-move refusal only. Every later failure retains the
 * same allocation and all completed/partial registrations; never rollback. */
kv_linux_cleanup_phase *kv_linux_cleanup_phase_start(kv_linux_owned_worker_result **owned);
int kv_linux_cleanup_phase_poll(kv_linux_cleanup_phase *,unsigned max_wait_ms);
int kv_linux_cleanup_phase_current(kv_linux_cleanup_phase *);
int kv_linux_cleanup_phase_cancel(kv_linux_cleanup_phase *);
int kv_linux_cleanup_phase_move(kv_linux_cleanup_phase **from,kv_linux_cleanup_phase **to_null);
int kv_linux_cleanup_phase_observe(const kv_linux_cleanup_phase *,struct kv_linux_cleanup_phase_observation *);
/* Invalidates first. EBUSY retains the same allocation until every owned native
 * birth/channel and exact borrower has actually drained/unlinked. No CLOSED. */
int kv_linux_cleanup_phase_close(kv_linux_cleanup_phase **owned);
#endif
