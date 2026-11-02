#ifndef KNOWLEDGE_LINUX_SERVICE_ADMISSION_H
#define KNOWLEDGE_LINUX_SERVICE_ADMISSION_H
#include "verification-linux-service-transport.h"
#include "verification-linux-uid-history.h"

/* Serialized root-native admission actor. Owns a retained journal lock and
 * sealed input custody, never runs project code. A RESERVED reply is NOT an
 * execution or cleanup receipt. No public CLOSED/reset/retry operation exists.
 * Configuration and boot identity are native administrative inputs. V2 caller
 * epochs are clock-domain validated and can only shorten native policy epochs.
 * V1 remains admission-only and cannot transfer source custody. The caller must
 * maintain each connection until process returns; events are consumed once.
 */
typedef struct kv_linux_service_actor kv_linux_service_actor;
enum kv_linux_service_reply_kind { KV_REPLY_HELLO=1, KV_REPLY_RESERVED=2,
    KV_REPLY_STOP_REQUESTED=3, KV_REPLY_RECOVERY_REQUIRED=4, KV_REPLY_ERROR=5, KV_REPLY_OBSERVATION=6,
    KV_REPLY_INTENT_HELD=7, KV_REPLY_SIGNED_HISTORY=8, KV_REPLY_SIGNED_RESULT_BUNDLE=9 };
enum kv_linux_service_reason { KV_REASON_OK=0, KV_REASON_PROTOCOL=1, KV_REASON_PEER=2,
    KV_REASON_HISTORY=3, KV_REASON_UID_EXHAUSTED=4, KV_REASON_DEADLINE=5, KV_REASON_UNAVAILABLE=6 };
enum kv_linux_service_phase { KV_PHASE_NONE=0, KV_PHASE_RESERVED=1, KV_PHASE_RUNNING=2,
    KV_PHASE_STOPPING=3, KV_PHASE_PENDING=4, KV_PHASE_CLOSED=5 };
struct kv_linux_service_reply {
    uint32_t kind, reason, phase, protocol_version;
    uint64_t ordinal, work_deadline_ns, cleanup_deadline_ns;
    unsigned char connection_nonce[16];
    kv_linux_uid_reservation reservation;
};
kv_linux_service_actor *kv_linux_service_actor_open(const kv_linux_uid_configuration *,
    const unsigned char boot_id[16], const char **reason);
/* Fresh transport events transfer fd ownership, including on refusal. Replayed
 * or invalid events transfer no fd (a stale integer may already be reused).
 * Returns 0 for a representable reply, -1 for invalid API/inherited actor (event
 * and fd ownership remain with caller). Never retries
 * an ambiguous publication or releases/reopens the history lock on failure. */
int kv_linux_service_actor_process(kv_linux_service_actor *, const struct kv_linux_service_connection *,
    struct kv_linux_service_event *, uint64_t work_deadline_ns, uint64_t cleanup_deadline_ns,
    struct kv_linux_service_reply *);
/* Native dispatcher admission deadline, checked again immediately before and
 * after durable burn. A late publication stays pending without source claim. */
int kv_linux_service_actor_process_bounded(kv_linux_service_actor *, const struct kv_linux_service_connection *,
    struct kv_linux_service_event *, uint64_t work_deadline_ns, uint64_t cleanup_deadline_ns,
    uint64_t admission_deadline_ns, struct kv_linux_service_reply *);
int kv_linux_service_reply_encode(unsigned char out[128], const struct kv_linux_service_reply *);
/* Explicit v3 entries. Existing process/reply/claim_import remain v1/v2-only.
 * OPEN freezes effective epochs and the admission cap; BIND cannot renew them.
 * INTENT_HELD means sealed FD custody/PREHASH claims only, never content proof. */
int kv_linux_service_actor_process_v3(kv_linux_service_actor *, const struct kv_linux_service_connection *,
    struct kv_linux_service_event *, uint64_t work_deadline_ns, uint64_t cleanup_deadline_ns,
    struct kv_linux_service_reply *);
int kv_linux_service_actor_process_v3_bounded(kv_linux_service_actor *, const struct kv_linux_service_connection *,
    struct kv_linux_service_event *, uint64_t work_deadline_ns, uint64_t cleanup_deadline_ns,
    uint64_t admission_deadline_ns, struct kv_linux_service_reply *);
int kv_linux_service_reply_encode_v3(unsigned char out[128], const struct kv_linux_service_reply *);
/* Drive even when no packets arrive or an output queue is full. Only local
 * input custody is dropped. Claimed importer/runtime custody is independent;
 * tick never closes history or proves those processes have exited. */
int kv_linux_service_actor_tick(kv_linux_service_actor *);
uint64_t kv_linux_service_actor_next_deadline(const kv_linux_service_actor *);
/* Original connection snapshot, before slot reuse. Owner socket EOF cancels
 * local input even if its PID lives. Return 1 only for that exact owner;
 * caller must separately cancel any claimed process custody. */
int kv_linux_service_actor_abandon_connection(kv_linux_service_actor *,
    const struct kv_linux_service_connection *);
struct kv_linux_service_import {
    int source_fd, peer_pidfd;
    uint64_t source_bytes, work_deadline_ns, cleanup_deadline_ns;
    kv_linux_uid_reservation reservation;
};
/* Internal native one-shot handoff. Caller initializes both output fds to -1.
 * Invalid/replayed calls do not touch caller-owned fds. A valid claim is burned
 * before duplication; any failure keeps the journal pending and cannot retry.
 * Only clock-validated v2 reservations transfer custody; v1 remains admission
 * only. Success transfers both CLOEXEC fds to the fixed native importer launcher,
 * which must retain independent deadline/death/process custody. No source bytes
 * are read here; no caller receipt can authorize closure or authority execution. */
int kv_linux_service_actor_claim_import(kv_linux_service_actor *,
    const struct kv_linux_service_connection *, const kv_linux_uid_reservation *,
    struct kv_linux_service_import *);
/* Native-only immutable claim tuple; all digests remain unverified claims.
 * No public/JSON API can construct a live guard or select another generation. */
struct kv_linux_service_input_binding {
    kv_linux_uid_reservation reservation;
    uint64_t source_bytes, intent_bytes;
    uint64_t requested_work_deadline_ns, requested_cleanup_deadline_ns;
    uint64_t work_deadline_ns, cleanup_deadline_ns, admission_deadline_ns;
    uint64_t time_namespace_dev, time_namespace_ino;
    unsigned char source_sha256[32], manifest_sha256[32], directories_sha256[32], intent_sha256[32];
    unsigned char connection_nonce[16], session_id[16], generation[16];
};
typedef struct kv_linux_service_input_guard kv_linux_service_input_guard;
struct kv_linux_service_source_input {
    int source_fd, intent_fd, peer_pidfd, clock_namespace_fd;
    struct kv_linux_service_input_binding binding;
    kv_linux_service_input_guard *guard;
};
/* Initialize all four output FDs to -1 and guard=NULL. A structurally matching
 * owned ready claim is burned before current clock/peer observations and any
 * duplication; failed/late publication closes only new local FDs,
 * cannot retry, and leaves durable history pending. Output remains untouched
 * until the complete four-FD tuple and fresh native checks succeed. Claim also
 * permanently fences the generic connection reader before any endpoint/output
 * duplicate; the guard retains its own native control endpoint and cursor. */
int kv_linux_service_actor_claim_source_intent_v3(kv_linux_service_actor *,
    const struct kv_linux_service_connection *, const kv_linux_uid_reservation *,
    struct kv_linux_service_source_input *);
/* 1 current, 0 invalidated/expired, -1 invalid API or inherited owner. No actor
 * or connection-slot pointer is borrowed. Actor close invalidates the guard
 * but a provider-held reference stays callable until explicitly released.
 * Runtime current drains bounded authenticated STOP/OBSERVE packets through
 * that endpoint before and after clock/peer checks. A full budget without an
 * actual empty queue, malformed input, EOF or reply backpressure revokes. The
 * pending DATA reply never grants new authority. Runtime current uses effective
 * work, not the completed admission cap. The
 * parent's native poll invokes this; an inherited hash child must not do so.
 * All guard operations are serialized in that original process. A callback
 * borrows the pointer only while its provider still owns the returned ref;
 * release must not race a callback. This is not a thread-safe public handle. */
int kv_linux_service_input_current_v3(kv_linux_service_input_guard *,
    const struct kv_linux_service_input_binding *);
/* Verified opened-history administrative identity retained by this exact
 * native guard; never a caller label or a borrowed actor/history pointer.
 * 0 success, -1 refusal; fresh current checks bracket the finite DATA copy. */
int kv_linux_service_input_administrative_identity_v3(kv_linux_service_input_guard *,
    const struct kv_linux_service_input_binding *,struct kv_linux_uid_administrative_identity *);
/* Release the provider's single owned guard reference ONLY after all consumers
 * have drained. Clears *guard; does not close the provider's four owned FDs or
 * attest cleanup. No ref-acquire/reset/rebind interface exists. */
int kv_linux_service_input_guard_release(kv_linux_service_input_guard **guard);
/* Drops local fd custody only. Pending durable burn remains for native recovery. */
void kv_linux_service_actor_close(kv_linux_service_actor *);
#endif
