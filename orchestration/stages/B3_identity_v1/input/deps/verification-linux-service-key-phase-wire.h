#ifndef KNOWLEDGE_LINUX_SERVICE_KEY_PHASE_WIRE_H
#define KNOWLEDGE_LINUX_SERVICE_KEY_PHASE_WIRE_H
#include "verification-linux-service-key-wire.h"
#include "verification-linux-service-phase-wire.h"

/* Pure DATA helpers. First PREPARE can introduce only the transition/result/
 * roster bytes; all original birth fields must match the fixed v2 context.
 * A native receiver separately authenticates its held peer/credentials/state.
 * No parser constructs a phase owner, signing right or timely acceptance. */
int kv_linux_key_phase_prepare_validate(const unsigned char *,size_t,
    const unsigned char context[KV_LINUX_KEY_CONTEXT_BYTES],struct kv_linux_phase_binding *out);

#define KV_LINUX_KEY_SIGN_MESSAGE_BYTES 512
#define KV_LINUX_KEY_SIGN_FRAME_BYTES 640
enum kv_linux_key_sign_kind {KV_LINUX_KEY_SIGN_REQUEST=1,KV_LINUX_KEY_SIGNED=2};
struct kv_linux_key_final_data {
    unsigned char phase_transcript_sha256[32],finalization_nonce[32];
    unsigned char service_generation_sha256[32],batch_nonce[16];
};
int kv_linux_key_sign_message_encode(unsigned char out[KV_LINUX_KEY_SIGN_MESSAGE_BYTES],
    const unsigned char context[KV_LINUX_KEY_CONTEXT_BYTES],const struct kv_linux_phase_binding *,
    const unsigned char public_key[32],const struct kv_linux_key_final_data *);
int kv_linux_key_sign_message_validate(const unsigned char *,size_t,
    const unsigned char context[KV_LINUX_KEY_CONTEXT_BYTES],const struct kv_linux_phase_binding *,
    const unsigned char public_key[32]);
/* Frame parser validates finite shape only; caller independently validates the
 * message, authenticates the actual sender and verifies a SIGNED signature. */
int kv_linux_key_sign_frame_encode(unsigned char out[KV_LINUX_KEY_SIGN_FRAME_BYTES],
    enum kv_linux_key_sign_kind,const unsigned char message[KV_LINUX_KEY_SIGN_MESSAGE_BYTES],
    const unsigned char *signature_or_null);
int kv_linux_key_sign_frame_validate(const unsigned char *,size_t,enum kv_linux_key_sign_kind,
    const unsigned char expected_message[KV_LINUX_KEY_SIGN_MESSAGE_BYTES],unsigned char *signature_out_or_null);
#endif
