#ifndef KNOWLEDGE_LINUX_SERVICE_SESSION_FRONT_H
#define KNOWLEDGE_LINUX_SERVICE_SESSION_FRONT_H
#include "verification-linux-service-daemon.h"

typedef struct kv_linux_session_front kv_linux_session_front;
/* Diagnostic DATA only. None of these counts is cleanup or acceptance proof. */
struct kv_linux_session_front_observation {
    unsigned retained,delivery_enabled,adopted_caller_bounds;
    uint64_t births,replies_relayed,failed_sessions;
    int stopping,failed;
};
/* New, admission-only source slice. Fixed single-threaded native root front;
 * protected installation/client authentication and full provider/F dispatch
 * are NOT implemented or qualified here. No executable/path/callback/token
 * factory exists. Configuration paths are copied bounded administrative
 * history settings, never socket-derived. Listener is an administrative
 * nonblocking AF_UNIX SEQPACKET listener with PASSCRED set before listen.
 *
 * The front creates no actor/transport/history owner. Each raw accepted FD
 * enters a new atomic-pidfd native child; only after the private birth gate
 * and descriptor allowlist does that child create its original opaque owners.
 * The child is the sole public reader. The front retains a SEND-ONLY socket
 * duplicate and relays exactly native128 admission DATA from its held child.
 * There is no public lookup, recovered acceptance or finalization constructor.
 */
kv_linux_session_front *kv_linux_session_front_open(int listener,
    const kv_linux_uid_configuration *,const struct kv_linux_daemon_policy *);
/* Native outer loop only: no journal/actor/fsync call. At most four accepts,
 * four private packets/session and one public send/session; wait<=1000ms.
 * Original setup/W/C are frozen at accept. Before actor open/burn the child's
 * validated HELLO may only shorten W/C, acknowledged by this same front.
 * Setup is never extended. Deadline/STOP/death disables delivery BEFORE
 * negative cancellation. Late child DATA is discarded, not timely success.
 */
int kv_linux_session_front_poll(kv_linux_session_front *,unsigned max_wait_ms);
int kv_linux_session_front_observe(const kv_linux_session_front *,
    struct kv_linux_session_front_observation *);
int kv_linux_session_front_stop(kv_linux_session_front *);
/* EBUSY retains the exact front/atomic child handles until actual pidfd reap
 * AND private EOF. A timeout/kill/exit0 never releases UIDs or proves cleanup.
 * Child fsync/D-state may outlive caller C. No PID-only signal fallback. */
int kv_linux_session_front_close(kv_linux_session_front **owned);
#endif
