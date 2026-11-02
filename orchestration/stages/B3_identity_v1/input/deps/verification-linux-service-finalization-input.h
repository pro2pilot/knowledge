#ifndef KNOWLEDGE_LINUX_SERVICE_FINALIZATION_INPUT_H
#define KNOWLEDGE_LINUX_SERVICE_FINALIZATION_INPUT_H
#include "verification-linux-service-finalization.h"
#include "verification-linux-service-cleanup-phase-input.h"
#include "verification-linux-service-key-phase-wire.h"
/* PRIVATE OUTPUT ONLY. No public constructor accepts these records, a history,
 * descriptor/path, callback, caller message or copied completion observation. */
struct kv_linux_finalization_seed {
    kv_linux_owned_worker_result *result;
    struct kv_linux_cleanup_phase_seed phase;
    unsigned char transition_nonce[32],phase_transcript_sha256[32];
};
struct kv_linux_finalization_persistence_material {
    unsigned char pending_record[640],message[KV_LINUX_KEY_SIGN_MESSAGE_BYTES],signature[64];
    unsigned char native_closure_sha256[32];
};
/* Structural matches: Boolean1/0, pure, original process and reciprocal owner. */
int kv_linux_finalization_phase_matches(const kv_linux_finalization *,const kv_linux_cleanup_phase *);
int kv_linux_finalization_phase_slot_matches(const kv_linux_finalization *,kv_linux_cleanup_phase *const *);
int kv_linux_finalization_guard_matches(const kv_linux_finalization *,const kv_linux_service_input_guard *);
int kv_linux_finalization_key_matches(const kv_linux_finalization *,const kv_linux_key_process *);
int kv_linux_finalization_closing_matches(const kv_linux_finalization *,const kv_linux_cleanup_phase *);
int kv_linux_finalization_confirmed_access_matches(const kv_linux_finalization *,const kv_linux_service_input_guard *);
int kv_linux_finalization_key_data(const kv_linux_finalization *,const kv_linux_key_process *,struct kv_linux_key_final_data *out);
int kv_linux_finalization_persistence_data(const kv_linux_finalization *,const kv_linux_service_input_guard *,
    struct kv_linux_finalization_persistence_material *out);
/* Private same-original-F historical DATA copy. Fresh actual read-access and
 * all native closure facts bracket the copy. This neither renews W/C nor
 * signs/persists/confirms/reconstructs a decision. Public export keeps its
 * original-C contract. Caller needs an independently authenticated read route. */
int kv_linux_finalization_read_confirmed(kv_linux_finalization *,
    unsigned char out[KV_LINUX_FINALIZATION_SIGNED_BYTES]);
/* Same F/read lifetime; signed576 followed by canonical result transcript.
 * Transcript hash MUST equal this F's signed result_sha256. All output stays
 * untouched on refusal. No new decision, key, SIGN or persistence is made. */
int kv_linux_finalization_read_bundle(kv_linux_finalization *,unsigned char *out,size_t capacity,size_t *used);

/* Only positive phase entrypoints after finalizer bind. Stale public phase
 * mutators refuse without effects; actual component revocation remains legal. */
int kv_linux_cleanup_phase_finalization_bind(kv_linux_cleanup_phase *,kv_linux_finalization *);
int kv_linux_cleanup_phase_finalization_matches(const kv_linux_cleanup_phase *,const kv_linux_finalization *);
int kv_linux_cleanup_phase_finalization_poll(kv_linux_cleanup_phase *,kv_linux_finalization *,unsigned max_wait_ms);
int kv_linux_cleanup_phase_finalization_current(kv_linux_cleanup_phase *,kv_linux_finalization *);
int kv_linux_cleanup_phase_finalization_guard(kv_linux_cleanup_phase *,const kv_linux_finalization *);
int kv_linux_cleanup_phase_finalization_seed(kv_linux_cleanup_phase *,kv_linux_finalization *,struct kv_linux_finalization_seed *out);
int kv_linux_cleanup_phase_finalization_work_drained(const kv_linux_cleanup_phase *,const kv_linux_finalization *);
int kv_linux_cleanup_phase_finalization_all_drained(const kv_linux_cleanup_phase *,const kv_linux_finalization *);
int kv_linux_cleanup_phase_finalization_cancel(kv_linux_cleanup_phase *,kv_linux_finalization *);
int kv_linux_cleanup_phase_finalization_close(kv_linux_cleanup_phase **actual_owned_slot,kv_linux_finalization *);

/* Sole native request; build bytes from actual key/phase/same-finalizer DATA. */
int kv_linux_key_finalization_start(kv_linux_key_process *,kv_linux_execution *,kv_linux_owned_worker_result *,
    kv_linux_cleanup_phase *,kv_linux_finalization *);
int kv_linux_key_finalization_copy_signed(kv_linux_key_process *,kv_linux_execution *,kv_linux_owned_worker_result *,
    kv_linux_cleanup_phase *,kv_linux_finalization *,unsigned char message[KV_LINUX_KEY_SIGN_MESSAGE_BYTES],unsigned char signature[64]);

/* Actual guard/history bridge, no actor storage/config/path/caller reservation.
 * Generation is native-birth DATA, not service authentication. Persistence gets
 * exact fixed material from the pure counterpart above. */
int kv_linux_service_input_finalization_generation(kv_linux_service_input_guard *,kv_linux_owned_worker_result *,
    kv_linux_cleanup_phase *,kv_linux_finalization *,unsigned char out[32]);
int kv_linux_service_input_finalization_originals_retired(const kv_linux_service_input_guard *,
    const kv_linux_owned_worker_result *,const kv_linux_cleanup_phase *,const kv_linux_finalization *);
int kv_linux_service_input_finalization_persist(kv_linux_service_input_guard *,kv_linux_owned_worker_result *,
    kv_linux_cleanup_phase *,kv_linux_finalization *);
/* Confirmed same-live historical reading only: actual endpoint/revision,
 * peer/clock/history access, no renewed W/C or signing/persistence/acceptance. */
int kv_linux_service_input_finalization_read_access(kv_linux_service_input_guard *,kv_linux_owned_worker_result *,
    kv_linux_cleanup_phase *,kv_linux_finalization *);
#endif
