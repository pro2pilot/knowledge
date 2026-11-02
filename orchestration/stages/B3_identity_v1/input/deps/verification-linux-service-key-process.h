#ifndef KNOWLEDGE_LINUX_SERVICE_KEY_PROCESS_H
#define KNOWLEDGE_LINUX_SERVICE_KEY_PROCESS_H
#include "verification-linux-service-semantic-plan.h"
#include <stdint.h>
#include <sys/types.h>

typedef struct kv_linux_key_process kv_linux_key_process;
struct kv_linux_key_pins {unsigned char executable[32];};
/* Diagnostic DATA, never a native key/signing/terminal capability. A historical
 * registration flag does not establish current; later failures stay visible. */
struct kv_linux_key_observation {
    pid_t pid;
    int failed,cancelled,reaped,exit_code;
    int preparation_eof,control_eof,diagnostic_eof;
    int realm_admitted,ordinary_ready,release_sent,public_registered;
    uint64_t work_deadline_ns,cleanup_deadline_ns;
    unsigned char public_key[32];
};
/* Reviewed first slice, not a qualified production dispatcher. Sole genuine
 * plan move precedes FD/fork work. NULL leaves *owned unchanged. Every later
 * failure returns retained state for actual native drain. Fixed root setup
 * creates a new owner0 userns before ordinary drop; no caller DATA/FD/bool can
 * substitute. It execs only the pinned fixed cold ELF with empty environment.
 * Initial entry can generate one key after finite live release; no signing,
 * worker command or cleanup-epoch extension is exposed. Root ancestors trusted;
 * same-host-UID signals remain DoS. Supported owner is single-threaded, keeps
 * SIGCHLD default without SA_NOCLDWAIT and exclusively reaps its own children.
 * Atomic CLONE_PIDFD birth never falls back to a recycled numeric target;
 * unexpected external reap remains unconfirmed. APIs are getpid-bound. */
kv_linux_key_process *kv_linux_key_start(const struct kv_linux_key_pins *,kv_linux_semantic_plan_lease **owned);
/* 0 active, 1 exact reap + all actual EOF, -1 unconfirmed. Failed starts still
 * own their lease/child/handles and must be polled. Original work never renews. */
int kv_linux_key_poll(kv_linux_key_process *);
int kv_linux_key_cancel(kv_linux_key_process *);
/* Fresh serialized owner-local check after PUBLIC, never a transferable permit
 * or terminal/signing authority. Drains pending protocol/diagnostics and checks
 * the actual retained birth, realm and original plan/peer/clock/work again.
 * EAGAIN means no PUBLIC yet; dynamic refusal is sticky and cancels retained
 * state. Consumers must revalidate this same held object at their use point. */
int kv_linux_key_current(kv_linux_key_process *);
/* Pure sole-pointer move into a NULL destination. No allocation/FD/current
 * work; invalid, occupied, self and inherited calls leave both unchanged.
 * A failed object may move for cleanup; moving never revives authority. */
int kv_linux_key_move(kv_linux_key_process **from,kv_linux_key_process **to_null);
int kv_linux_key_observe(const kv_linux_key_process *,struct kv_linux_key_observation *);
/* Invalidates/cancels first; EBUSY through actual reap + control/diagnostic/prep
 * EOF. Close private FDs before sole plan release. Inherited refusal is pure. */
int kv_linux_key_close(kv_linux_key_process **owned);
#endif
