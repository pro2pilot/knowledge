#ifndef KNOWLEDGE_LINUX_SERVICE_ATTEMPT_IDENTITY_H
#define KNOWLEDGE_LINUX_SERVICE_ATTEMPT_IDENTITY_H
#include <stddef.h>
#include <stdint.h>

#define KV_LINUX_ATTEMPT_PENDING_BYTES 640
typedef struct kv_linux_request_identity_cap kv_linux_request_identity_cap;
typedef struct kv_linux_attempt_identity kv_linux_attempt_identity;
struct kv_linux_attempt_identity_observation {
    uint32_t schema_version; /* 1 */
    int record_created, failed;
    int semantic_authority_available, execution_available, ack_released; /* Always 0. */
};

/* Only a real, owned request-v2 provider capability can create an identity.
 * No input/hash/current-callback/serialized-record constructor exists.
 * Allocate first; consume then burns the capability before fresh current.
 * NULL leaves *owned_cap caller-owned (possibly consumed/failed) for release.
 * After successful consume ownership moves and *owned_cap becomes NULL.
 * Every later outcome returns a retained object, possibly failed: observe it.
 * The provider keeps its native allocation/guard and close returns EBUSY until
 * identity_close releases this sole lease. No execution or durable state exists.
 * The serialized native owner must disable ambient crypto configuration before
 * any crypto use; NO_LOAD_CONFIG here cannot undo earlier initialization. */
kv_linux_attempt_identity *kv_linux_attempt_identity_create(kv_linux_request_identity_cap **owned_cap);
/* Pure diagnostic DATA, not a fresh custody check. Inherited callers refused. */
int kv_linux_attempt_identity_observe(const kv_linux_attempt_identity *,struct kv_linux_attempt_identity_observation *);
/* 0 current, -1 sticky refusal. Uses the real retained provider capability. */
int kv_linux_attempt_identity_current(kv_linux_attempt_identity *);
/* Exact finite DATA record only. Requires fresh current before/after local
 * assembly. Failure leaves the entire output untouched; capacity must be 640.
 * Native revision=1, ACK=0, REQUEST_BOUND_PENDING. No terminal/success state.
 * Public identity-instance nonce is neither a service lifetime proof nor token. */
int kv_linux_attempt_identity_export_pending(kv_linux_attempt_identity *,unsigned char *out,size_t capacity);
/* Structural DATA validation only. A valid record cannot recreate a capability,
 * establish native origin/current/semantics, or recover timely acceptance. */
int kv_linux_attempt_pending_validate(const unsigned char *,size_t);
/* Pointer-to-pointer, idempotent NULL close. Sticky invalidation begins at the
 * first owned close. EBUSY retains the pointer/cap/provider while a semantic
 * lease exists. Inherited close leaves both pointer and original provider lease
 * untouched. Never clears either one-shot mint latch. */
int kv_linux_attempt_identity_close(kv_linux_attempt_identity **owned);
#endif
