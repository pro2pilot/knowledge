#ifndef KNOWLEDGE_LINUX_SERVICE_DAEMON_H
#define KNOWLEDGE_LINUX_SERVICE_DAEMON_H
#include "verification-linux-service-admission.h"

#define KV_LINUX_DAEMON_CONNECTIONS 16
typedef struct kv_linux_service_daemon kv_linux_service_daemon;
struct kv_linux_daemon_policy {
    uid_t authorized_uid; gid_t authorized_gid;
    uint64_t max_source_bytes, setup_ns, work_ns, cleanup_ns;
};
enum kv_linux_daemon_event {
    KV_DAEMON_INPUT_DROPPED=1, KV_DAEMON_RESERVATION=2, KV_DAEMON_STOP_REQUESTED=4
};
/* Fixed native dispatcher. Actor/listener are administrative inputs; no socket
 * packet chooses a path, UID, executable or native proof. Listener must already
 * be a nonblocking bound/listening AF_UNIX SOCK_SEQPACKET socket. Actor remains
 * caller-owned. Duplicated listener and all connections are dispatcher-owned.
 */
kv_linux_service_daemon *kv_linux_service_daemon_open(kv_linux_service_actor *,
    int listener, const struct kv_linux_daemon_policy *);
/* Bounded native polling, at most one packet/reply per slot and four accepts per
 * iteration. Returns event flags or -1; never a cleanup/closure receipt. The
 * fixed service main MUST cancel independent importer/runtime custody on
 * INPUT_DROPPED, STOP_REQUESTED or failure, and poll its held birth/EOF/deadline
 * custody independently every iteration. Disk stalls are not proven bounded.
 */
int kv_linux_service_daemon_poll(kv_linux_service_daemon *, unsigned max_wait_ms);
/* Only validated v2 offers are claimable, once, using actor authentication.
 * Caller initializes output fds to -1 and owns them on success. No runtime
 * authority, source sealing or journal closure follows from this handoff. */
int kv_linux_service_daemon_claim_import(kv_linux_service_daemon *, struct kv_linux_service_import *);
void kv_linux_service_daemon_request_stop(kv_linux_service_daemon *);
/* Closes transport/input only; caller must retain claimed custody until its
 * own native completion. The durable journal remains pending. */
int kv_linux_service_daemon_close(kv_linux_service_daemon *);
#endif
