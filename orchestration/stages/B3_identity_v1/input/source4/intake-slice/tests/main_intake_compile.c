/* COMPILE ONLY. No main and no native subject execution. The exact inherited
 * fixture retains all core bodies; this table retains all seven intake bodies. */
#include "../../tests/main_h_core_compile.c"
#include "../main-intake.inc"
struct mi_compile_references {
 int (*capture)(int,const struct mi_admin *);
 int (*accept_original)(void);
 int (*receive_original)(void);
 int (*cancel_original)(void);
 int (*finish_original)(void);
 int (*core_offer_original)(void);
 void (*stop_original)(void);
};
const struct mi_compile_references mi_compile_only_api={mi_main_capture,
 mi_accept_original,mi_receive_original,mi_cancel_original,mi_finish_original,
 mi_core_offer_original,mi_stop_original};
