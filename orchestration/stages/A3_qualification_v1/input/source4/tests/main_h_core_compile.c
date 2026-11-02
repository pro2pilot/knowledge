/* TRANSLATION ONLY. This file deliberately has no main(), is compiled to an
 * object and is NEVER linked or executed as a Main/H subject. It exercises
 * the real Linux x86_64 headers and native prototypes, without test macros. */
#include "../main-h-birth-core.inc"

/* Typed external data references retain the actual native bodies at -O2.
 * This is a compile fixture, not an exported API of the private include. */
struct mh_compile_references {
    int (*spawn)(void);
    int (*release)(void);
    int (*cancel)(void);
    int (*progress)(void);
    int (*finish)(void);
    void (*stop)(void);
    int (*drop_checked)(const struct mh_slot *, int, int, int);
};
const struct mh_compile_references mh_compile_only_api = {
    mh_spawn_original, mh_release_original, mh_cancel_original,
    mh_progress_original, mh_finish_original, mh_stop_original,
    mh_child_drop_checked
};
