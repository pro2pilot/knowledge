#ifndef KNOWLEDGE_LINUX_SERVICE_INPUT_HASH_H
#define KNOWLEDGE_LINUX_SERVICE_INPUT_HASH_H
#include "verification-linux-service-intent.h"
#include <stddef.h>
typedef struct kv_linux_input_hash_process kv_linux_input_hash_process;
struct kv_linux_input_hash_expected {
    struct kv_linux_intent_expected intent;
    uint64_t source_bytes, intent_bytes;
    unsigned char intent_sha256[32];
};
/* Parent-only native serialized owner. Provider retains its opaque actor guard
 * and this callback context until all consumers drain and hash_close succeeds.
 * Child never calls an inherited actor guard or project/JS callback. */
typedef int (*kv_linux_input_hash_owner_check)(void *,const struct kv_linux_input_hash_expected *);
struct kv_linux_input_hash_input {
    int source_fd,intent_fd,peer_pidfd,clock_namespace_fd; /* borrowed */
    struct kv_linux_input_hash_expected expected;
    kv_linux_input_hash_owner_check owner_check;
    void *owner_context;
};
struct kv_linux_input_hash_observation {
    int reaped,channel_eof,report_received,cancelled,failed,consumed,exit_code;
};
struct kv_linux_input_hash_result {
    unsigned char source_sha256[32],intent_sha256[32],body_sha256[32];
    uint64_t source_bytes,intent_bytes;
};
/* Fixed native byte hashing only, no filesystem paths, JSON, commands or UID
 * selection. NULL means pre-fork refusal. Every postfork outcome retains an
 * owned object, including pidfd/start-barrier failure. Caller inputs untouched.
 * A fixed daemon must disable ambient crypto config before any crypto use;
 * the child's NO_LOAD_CONFIG cannot undo a previously initialized parent. */
kv_linux_input_hash_process *kv_linux_input_hash_start(const struct kv_linux_input_hash_input *);
/* Explicit KVLREQ2/version2 variant. The original start remains KVLINT1-only;
 * expected format is selected by this native entry, never autodetected from
 * project bytes. Result intent_* fields denote the full request envelope. */
kv_linux_input_hash_process *kv_linux_input_hash_start_request_v2(const struct kv_linux_input_hash_input *);
/* Bounded nonblocking observations, max_wait<=1000. Failures remain sticky and
 * retain child/channel custody. Work/cleanup epochs never refresh. */
int kv_linux_input_hash_poll(kv_linux_input_hash_process *,unsigned max_wait_ms);
int kv_linux_input_hash_observe(const kv_linux_input_hash_process *,struct kv_linux_input_hash_observation *);
int kv_linux_input_hash_cancel(kv_linux_input_hash_process *);
/* One-shot DATA observation only, after exact report+exit0+reap+EOF and fresh
 * native owner/clock/peer checks. No authority, source-readonly or finality. */
int kv_linux_input_hash_claim(kv_linux_input_hash_process *,struct kv_linux_input_hash_result *);
/* EBUSY until actual reap+channel EOF. No input close, retry, directory removal
 * or durable history closure. Guard/context may be released only after this. */
int kv_linux_input_hash_close(kv_linux_input_hash_process *);
#endif
