#ifndef KNOWLEDGE_LINUX_SERVICE_TRANSPORT_H
#define KNOWLEDGE_LINUX_SERVICE_TRANSPORT_H
#include <stdint.h>
#include <sys/types.h>

/* Native broker admission component, not a service/backend availability flag.
 * A successful receive is only a transport event. The lifecycle owner must
 * recheck peer liveness immediately before dispatch and independently enforce
 * work/cleanup epochs, source custody, UID history and native teardown proof.
 * No packet can select a privileged path, UID, executable or CLOSED transition.
 */
#define KV_LINUX_SERVICE_FRAME_BYTES 64
#define KV_LINUX_SERVICE_FRAME_V1_BYTES 64
#define KV_LINUX_SERVICE_FRAME_V2_BYTES 80
#define KV_LINUX_SERVICE_FRAME_V3_BYTES 288
#define KV_LINUX_SERVICE_MAX_SOURCE_BYTES UINT64_C(2147483648)
#define KV_LINUX_SERVICE_MAX_INTENT_BYTES UINT64_C(1048704)
/* Separate explicit runtime endpoint. Legacy ordinary client/control.sock
 * stays admission-only; no alias, fallback or implicit runtime upgrade. */
#define KV_LINUX_SERVICE_RUNTIME_SOCKET "/run/knowledge-linux-service/runtime.sock"
#define KV_LINUX_SERVICE_RUNTIME_SOCKET_NAME "runtime.sock"
struct kv_linux_service_clock_identity {
    unsigned char boot_id[16];
    uint64_t time_namespace_dev, time_namespace_ino;
    int namespace_fd; /* Owned held NSFS descriptor, CLOEXEC; close explicitly. */
};
/* Actual native CLOCK_MONOTONIC domain, never caller labels. Failure is closed;
 * the caller initializes namespace_fd=-1 and must not overwrite a live clock. */
int kv_linux_service_clock_open(struct kv_linux_service_clock_identity *);
void kv_linux_service_clock_close(struct kv_linux_service_clock_identity *);
enum kv_linux_service_op { KV_LINUX_HELLO = 1, KV_LINUX_OPEN = 2, KV_LINUX_STOP = 3, KV_LINUX_OBSERVE = 4, KV_LINUX_BIND_INTENT = 5,
    KV_LINUX_READ_CONFIRMED = 6, KV_LINUX_READ_RESULT_BUNDLE = 7 /* Runtime only; bytes=read deadline, no rights. */ };
enum kv_linux_service_state { KV_LINUX_EXPECT_HELLO, KV_LINUX_READY, KV_LINUX_OPENED, KV_LINUX_STOPPED, KV_LINUX_POISONED, KV_LINUX_INTENT_HELD };
/* Finite wire claims, never content authentication or selectable authority.
 * Native actor must match reservation to its own current state before use. */
struct kv_linux_service_v3_binding {
    uint64_t allocation_sequence, intent_bytes;
    uint32_t authority_uid, worker_uid;
    unsigned char attempt_nonce[32], source_sha256[32], manifest_sha256[32], directories_sha256[32], intent_sha256[32];
};
struct kv_linux_service_control_anchor;
struct kv_linux_service_connection {
    int socket_fd, peer_pidfd;
    pid_t peer_pid;
    uid_t peer_uid;
    gid_t peer_gid;
    enum kv_linux_service_state state;
    uint64_t next_ordinal, processed_ordinal, max_source_bytes;
    unsigned char nonce[16];
    unsigned char session_id[16]; /* Native-only random connection identity. */
    uint32_t protocol_version;
    uint64_t requested_work_deadline_ns, requested_cleanup_deadline_ns;
    struct kv_linux_service_clock_identity clock;
    uint64_t v3_source_bytes;
    unsigned char v3_source_hashes[96];
    /* Opaque original-process transport ownership. Public fields are mirrors;
     * they cannot construct a native cursor or reopen a claimed reader. Public
     * pidfds are diagnostic mirrors: native watches always duplicate the
     * retained anchor handle; pidfd fstat inode equality proves no identity. */
    struct kv_linux_service_control_anchor *control_anchor;
};
struct kv_linux_service_event {
    struct kv_linux_service_connection *connection;
    unsigned char connection_nonce[16];
    unsigned char session_id[16];
    enum kv_linux_service_op op;
    uint64_t ordinal, source_bytes;
    int source_fd; /* Receiver owns this CLOEXEC fd on success; otherwise -1.
                   * v3 BIND_INTENT uses this single slot for its intent FD. */
    uint32_t protocol_version;
    uint64_t requested_work_deadline_ns, requested_cleanup_deadline_ns;
    unsigned char caller_boot_id[16];
    int clock_domain_validated; /* Native receiver assertion, not a wire flag. */
    struct kv_linux_service_v3_binding binding;
};

/* Duplicates fd atomically CLOEXEC; caller retains ownership of its fd.
 * authorized_uid/gid/max_source_bytes come only from installed broker policy.
 * The owner must disconnect an initialized connection before reusing its storage;
 * each connection/event has one serialized native lifecycle owner.
 * SO_PEERPIDFD unsupported/denied/dead => refusal, never a PID-only fallback.
 */
int kv_linux_service_connect(struct kv_linux_service_connection *, int fd, uid_t authorized_uid,
                             gid_t authorized_gid, uint64_t max_source_bytes);
int kv_linux_service_peer_live(const struct kv_linux_service_connection *);
/* 1 event, 0 no packet yet (EAGAIN), -1 refusal; the native lifecycle owner must
 * consume the actual retained event before the next receive (EBUSY otherwise).
 * After source claim, only the owned private guard may read (EBUSY forever on
 * this generic interface). Malformed packets permanently poison admission.
 * Rejection closes all received descriptors, including truncated rights.
 * OPEN accepts metadata only, never reads opaque source bytes in privileged code.
 * The isolated importer must use pread, never a shared file offset.
 */
int kv_linux_service_receive(struct kv_linux_service_connection *, struct kv_linux_service_event *);
/* Explicit v3-only receiver. Legacy receive remains v1/v2-only. No existing
 * actor/daemon/client activation uses this entry. Every event transfers at most
 * one descriptor; old actors must reject version3 before burn/claim. */
int kv_linux_service_receive_v3(struct kv_linux_service_connection *, struct kv_linux_service_event *);
void kv_linux_service_disconnect(struct kv_linux_service_connection *);
/* Canonical encoder used by the fixed native client. Nonzero nonce is required. */
int kv_linux_service_frame(unsigned char out[KV_LINUX_SERVICE_FRAME_BYTES], enum kv_linux_service_op,
                           uint64_t ordinal, const unsigned char nonce[16], uint64_t source_bytes);
int kv_linux_service_frame_v2(unsigned char out[KV_LINUX_SERVICE_FRAME_V2_BYTES], enum kv_linux_service_op,
    uint64_t ordinal, const unsigned char nonce[16], uint64_t source_bytes,
    uint64_t work_deadline_ns, uint64_t cleanup_deadline_ns, const unsigned char boot_id[16]);
int kv_linux_service_frame_v3(unsigned char out[KV_LINUX_SERVICE_FRAME_V3_BYTES], enum kv_linux_service_op,
    uint64_t ordinal, const unsigned char nonce[16], uint64_t source_bytes,
    uint64_t work_deadline_ns, uint64_t cleanup_deadline_ns, const unsigned char boot_id[16],
    const struct kv_linux_service_v3_binding *); /* exact zero binding for nonartifact ops */
/* Explicit NEW runtime-only historical read codec. Legacy frame_v3 continues
 * to refuse op6. bytes in this wire is a fresh monotonic DATA delivery bound,
 * not an artifact size or a renewed WORK/cleanup epoch. Only a genuine claimed
 * runtime endpoint accepts it; the generic actor/receiver refuses it. */
int kv_linux_service_frame_read_confirmed(unsigned char out[KV_LINUX_SERVICE_FRAME_V3_BYTES],uint64_t ordinal,
    const unsigned char nonce[16],uint64_t read_deadline_ns,uint64_t original_work_ns,uint64_t original_cleanup_ns,
    const unsigned char boot_id[16]);
int kv_linux_service_frame_read_result_bundle(unsigned char out[KV_LINUX_SERVICE_FRAME_V3_BYTES],uint64_t ordinal,
    const unsigned char nonce[16],uint64_t read_deadline_ns,uint64_t original_work_ns,uint64_t original_cleanup_ns,
    const unsigned char boot_id[16]);
/* Revalidate live peer and native namespace identity before actor publication.
 * v1 has no caller-clock contract and always returns failure here. */
int kv_linux_service_clock_domain_live(const struct kv_linux_service_connection *);
#endif
