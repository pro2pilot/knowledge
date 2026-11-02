#ifndef KNOWLEDGE_LINUX_SERVICE_SEMANTIC_PLAN_H
#define KNOWLEDGE_LINUX_SERVICE_SEMANTIC_PLAN_H
#include "verification-linux-service-semantic-process.h"

/* Native ABI for the explicit closed native launch-inventory path. This does
 * not establish global host UID exclusivity or authorize keys/commands. */
typedef struct kv_linux_semantic_plan_lease kv_linux_semantic_plan_lease;

/* New explicit entry. The retained provider/identity/semantic lease must come
 * from the role-qualified request-v2 entry. The old start stays unqualified.
 * Sole ownership moves before role admission, FD duplication or fork. Every
 * post-move failure returns a retained process for actual native drain. */
kv_linux_semantic_process *kv_linux_semantic_start_role(
    const struct kv_linux_semantic_pins *,kv_linux_attempt_semantic_lease **owned);

/* Requires the same actual qualified process and complete native drain.
 * Shares the old borrowed-plan one-shot latch: neither API can mint a second
 * claim after the other has burned it. Pure arguments/owner/readiness precede
 * burn, then allocation/current and the final exclusive role CAS. Any dynamic
 * failure is permanent and leaves *out NULL. No DATA constructor exists. */
int kv_linux_semantic_claim_plan_lease(kv_linux_semantic_process *,
    kv_linux_semantic_plan_lease **out_null);

/* Pure owner-checked transfer. No FD/current/allocation work; inherited or
 * invalid calls leave both pointers unchanged. Failed/closing leases can move
 * for cleanup. A successful move is required before private launch handoff. */
int kv_linux_semantic_plan_lease_move(kv_linux_semantic_plan_lease **from,
    kv_linux_semantic_plan_lease **to_null);

/* Fresh original-work/peer/clock/transitive owner and exact exclusive sequence.
 * Failure is sticky. No fallback to a copied plan/report or renewed epoch. */
int kv_linux_semantic_plan_lease_current(kv_linux_semantic_plan_lease *);

/* Sole owned reference, pointer-to-pointer, inherited-owner pure refusal.
 * Native consumers must retain this until every actual birth and channel they
 * own drains. Release manages allocation lifetime; it is not their drain proof.
 * It never rearms a launch/claim or role sequence. semantic_close invalidates
 * and detaches the role, but returns EBUSY while this lease exists, BEFORE
 * closing private peer/clock/parser handles or releasing the transitive lease. */
int kv_linux_semantic_plan_lease_release(kv_linux_semantic_plan_lease **owned);
#endif
