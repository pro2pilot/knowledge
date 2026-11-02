#ifndef KNOWLEDGE_LINUX_SERVICE_SOURCE_PROVIDER_H
#define KNOWLEDGE_LINUX_SERVICE_SOURCE_PROVIDER_H
#include "verification-linux-service-admission.h"
#include "verification-linux-service-input-hash.h"
#include "verification-linux-service-custody.h"
#include "verification-linux-service-verify.h"

typedef struct kv_linux_source_provider kv_linux_source_provider;
enum kv_linux_provider_phase { KV_PROVIDER_HASHING=1, KV_PROVIDER_IMPORTING=2,
    KV_PROVIDER_VERIFYING=3, KV_PROVIDER_CONTENT_READY=4,
    KV_PROVIDER_RETAINED_UNCONFIRMED=5 };
/* Diagnostic DATA only. No serialized observation reconstructs a native owner
 * or grants authority. Content readiness never validates intent semantics. */
struct kv_linux_provider_observation {
    enum kv_linux_provider_phase phase;
    int failed,cancelled,closing;
    unsigned hash_starts,custody_starts,verify_starts; /* One-shot attempts. */
    int hash_started,custody_started,verify_started; /* Actual retained birth. */
    int hash_closed,verify_closed,keeper_closed,hash_claimed,content_claimed;
    struct kv_linux_service_input_binding binding;
    struct kv_linux_input_hash_observation hash;
    struct kv_linux_input_hash_result hashes;
    struct kv_linux_source_observation custody;
    int verify_reaped,verify_receipt_eof,verify_preparation_eof,verify_content_eof;
    int verify_failed,verify_exit_code;
    struct kv_linux_verify_content_observation content;
};
/* Fixed serialized root-native owner. Allocates and copies administrative pins
 * before the actor's atomic v3 claim, never retains actor/connection pointers.
 * NULL leaves no provider-owned resources; an unsuccessful actor claim may
 * already be consumed and is not retryable. Once claim succeeds, every later
 * failure returns the same retained object, even before any child was born.
 * The daemon must disable ambient crypto configuration before any crypto use.
 * No arbitrary input constructor, FD export, authority lease or reset exists. */
kv_linux_source_provider *kv_linux_source_provider_start(kv_linux_service_actor *,
    const struct kv_linux_service_connection *,const kv_linux_uid_reservation *,
    const struct kv_linux_import_pins *,const struct kv_linux_verify_pins *);
/* Explicit KVLREQ2/version2 byte-bound variant. Original start remains
 * KVLINT1-only. This still validates no request JSON/command semantics. */
kv_linux_source_provider *kv_linux_source_provider_start_request_v2(kv_linux_service_actor *,
    const struct kv_linux_service_connection *,const kv_linux_uid_reservation *,
    const struct kv_linux_import_pins *,const struct kv_linux_verify_pins *);
/* Explicit closed native launch-inventory variant. Mode is fixed before the
 * first child side effect and rooted in the SAME sole actor claim. Its private
 * role fence permits only the fixed importer -> verifier -> semantic chain;
 * raw semantic input extraction and old unqualified starts cannot upgrade it.
 * This is conditional on the supported exclusive UID-range deployment, not a
 * global host scan/proof, key permission, cleanup phase or terminal receipt. */
kv_linux_source_provider *kv_linux_source_provider_start_request_v2_role(kv_linux_service_actor *,
    const struct kv_linux_service_connection *,const kv_linux_uid_reservation *,
    const struct kv_linux_import_pins *,const struct kv_linux_verify_pins *);
/* Bounded observations, at most one stage transition; wait<=1000ms (each
 * actual component wait<=10ms). Continues retained cancellation/drain after
 * failure. No original epoch is renewed; kernel D-state/paused controller
 * autonomous deadlines are not qualified. Returns 0 or invalid API -1. */
int kv_linux_source_provider_poll(kv_linux_source_provider *,unsigned max_wait_ms);
int kv_linux_source_provider_observe(const kv_linux_source_provider *,struct kv_linux_provider_observation *);
/* 1 current source/content match, 0 not ready or sticky invalidation, -1 invalid
 * API/inherited caller. Actual use must call this, not trust an old observation.
 * Intent JSON semantics, authority commands and terminal history stay absent. */
int kv_linux_source_provider_current(kv_linux_source_provider *);
int kv_linux_source_provider_cancel(kv_linux_source_provider *);
/* Sticky cancellation. EBUSY until all hash/verifier children and channels,
 * then keeper birth/control EOF, are closed. Only then releases four input
 * descriptors, readonly root and guard. Never deletes artifacts, closes the
 * durable reservation or recycles UIDs. Retry close on the SAME live object. */
int kv_linux_source_provider_close(kv_linux_source_provider *);
#endif
