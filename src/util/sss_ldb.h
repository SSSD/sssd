#ifndef __SSS_LDB_H__
#define __SSS_LDB_H__

#include "config.h"

#ifdef LDB_MODULES_PATH_OVERRIDE
void sss_ldb_init_modules_path(void);
#else
#define sss_ldb_init_modules_path() do {} while(0)
#endif

#endif
