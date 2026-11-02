#ifndef KNOWLEDGE_LINUX_SERVICE_RUNTIME_FRONT_H
#define KNOWLEDGE_LINUX_SERVICE_RUNTIME_FRONT_H
#include "verification-linux-service-session-front.h"
#include "verification-linux-service-child-runtime.h"
typedef struct kv_linux_runtime_front kv_linux_runtime_front;
struct kv_linux_runtime_front_observation {
    unsigned retained,delivery_enabled,adopted_caller_bounds;
    uint64_t births,replies_relayed,failed_sessions;
    int stopping,failed;
};
/* New fixed native runtime route. Original atomic children create all opaque
 * owners locally. Administrative pins/path/policy are copied; no request picks
 * a privileged path/executable/UID. Caller owns listener/config. Parent does
 * no journal/content I/O, but does native /proc metadata checks. Fixed native
 * single-thread startup/no past threads and protected installation are explicit
 * program/deployment premises, not inferred from the one-thread proc check.
 * See audit13/RUNTIME_FRONT_DECISIONS_RU.md for exact unqualified boundaries. */
/* Listener MUST have the exact new runtime.sock kernel bind name; control.sock,
 * abstract, relative/trailing aliases refuse before any clone. Fixed Main also
 * owns/checks the protected held/named socket inode/no-alias namespace, closes
 * its original listener before first poll, and creates no other listener alias.
 * getsockname alone cannot attest a path's identity after privileged rename. */
kv_linux_runtime_front *kv_linux_runtime_front_open(int listener,
    const kv_linux_uid_configuration *,const struct kv_linux_daemon_policy *,
    const struct kv_linux_service_child_runtime_pins *);
int kv_linux_runtime_front_poll(kv_linux_runtime_front *,unsigned max_wait_ms);
int kv_linux_runtime_front_observe(const kv_linux_runtime_front *,struct kv_linux_runtime_front_observation *);
int kv_linux_runtime_front_stop(kv_linux_runtime_front *);
/* Disables delivery first; EBUSY retains exact atomic children until actual
 * reap+private EOF. Exit/kill/timeout never proves UID/work-scope closure. */
int kv_linux_runtime_front_close(kv_linux_runtime_front **owned);
#endif
