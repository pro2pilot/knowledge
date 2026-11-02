#ifndef KNOWLEDGE_LINUX_SERVICE_ATTEMPT_SEMANTIC_H
#define KNOWLEDGE_LINUX_SERVICE_ATTEMPT_SEMANTIC_H
#include "verification-linux-service-attempt-identity.h"

typedef struct kv_linux_attempt_semantic_lease kv_linux_attempt_semantic_lease;
struct kv_linux_attempt_semantic_input {
    int request_fd,peer_pidfd,clock_namespace_fd;
    unsigned char pending_record[KV_LINUX_ATTEMPT_PENDING_BYTES];
};
/* Original serialized native owner only. All APIs return 0 or -1. There is no
 * caller-FD, record, callback, or deserialized lease constructor. Initialize
 * *out=NULL. Allocate inert state, then burn the identity's permanent claim
 * latch before fresh current. Failure after burn is sticky and cannot retry.
 * A successful lease retains the identity and its sole provider capability. */
int kv_linux_attempt_identity_claim_semantic(kv_linux_attempt_identity *,kv_linux_attempt_semantic_lease **out);
/* Pure owner-checked pointer transfer for an inert native launcher process.
 * No allocation, current check or FD operation. *to must be NULL; from!=to.
 * Success moves *from into *to and clears *from. Invalid/inherited refusal
 * leaves both pointers untouched. Failed/closing state is preserved: moving
 * an invalidated lease permits retained cleanup only, never authority. */
int kv_linux_attempt_semantic_lease_move(kv_linux_attempt_semantic_lease **from,kv_linux_attempt_semantic_lease **to);
/* Unqualified input entry; a role-qualified native provider refuses this path
 * before extraction. Its supported fixed launcher uses the separate private
 * role bridge, sharing this one-shot input latch. Initialize all three FD
 * fields to -1. Pure invalid output/inherited calls do
 * not burn. A ready call burns before the actual capability's one-shot input
 * claim. Success transfers three CLOEXEC descriptors plus the identity's
 * private frozen 640-byte DATA after final current. Failure closes local FDs
 * only and leaves the ENTIRE output untouched; the spent lease remains owned.
 * Request duplicates share offsets: use bounded pread and actual seal checks.
 * These descriptors and DATA do not grant semantic/command/terminal authority. */
int kv_linux_attempt_semantic_lease_claim_input(kv_linux_attempt_semantic_lease *,struct kv_linux_attempt_semantic_input *out);
/* Fresh actual retained provider/current; refusal is sticky. */
int kv_linux_attempt_semantic_lease_current(kv_linux_attempt_semantic_lease *);
/* Pointer-to-pointer, NULL idempotent; inherited refusal leaves everything
 * untouched. Release never resets either one-shot latch and is NOT drain proof.
 * Supported native launcher start must move lease** into its retained process
 * before fork/FD side effects. It alone releases after actual born-child reap
 * and every output/preparation EOF, closing its input FDs first. Postfork failure
 * retains process+lease. Standalone lease enforces allocation retention only;
 * no caller boolean or callback may stand in for native consumer drain. */
int kv_linux_attempt_semantic_lease_release(kv_linux_attempt_semantic_lease **owned);
#endif
