#define _GNU_SOURCE
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>

#include "util/util.h"

const char *debug_prg_name = "sssd";
int debug_level = 0;

void debug_fn(const char *format, ...)
{
    va_list ap;
    char *s = NULL;

    va_start(ap, format);
    vasprintf(&s, format, ap);
    va_end(ap);

    /*write(state.fd, s, strlen(s));*/
    fprintf(stderr, s);
    free(s);
}

void ldb_debug_messages(void *context, enum ldb_debug_level level,
                        const char *fmt, va_list ap)
{
    int loglevel = -1;
    switch(level) {
    case LDB_DEBUG_FATAL:
        loglevel = 0;
        break;
    case LDB_DEBUG_ERROR:
        loglevel = 1;
        break;
    case LDB_DEBUG_WARNING:
        loglevel = 3;
        break;
    case LDB_DEBUG_TRACE:
        loglevel = 9;
        break;
    }

    DEBUG(loglevel, (fmt, ap));
}
