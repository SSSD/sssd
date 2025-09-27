#include "config.h"

#ifdef LDB_MODULES_PATH_OVERRIDE

#include <stdlib.h>
#include <stdatomic.h>
#include "util/debug.h"

void sss_ldb_init_modules_path(void)
{
    static atomic_flag initialized = ATOMIC_FLAG_INIT;
    if (atomic_flag_test_and_set(&initialized) == false) {
        if (setenv("LDB_MODULES_PATH", LDB_MODULES_PATH_OVERRIDE, 0) != 0) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Failed to set LDB_MODULES_PATH\n");
        }
    }
}

#endif
