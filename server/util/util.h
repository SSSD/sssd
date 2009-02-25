#ifndef __SSSD_UTIL_H__
#define __SSSD_UTIL_H__

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include "config.h"
#include "talloc.h"
#include "tevent.h"

extern const char *debug_prg_name;
extern int debug_level;
void debug_fn(const char *format, ...);

#define SSSD_DEBUG_OPTS \
		{"debug-level",	'd', POPT_ARG_INT, &debug_level, 0, \
		 "Debug level", NULL},

#define DEBUG(level, body) do { \
    if (level <= debug_level) { \
        debug_fn("[%s] [%s] (%d): ", \
                 debug_prg_name, __FUNCTION__, level); \
        debug_fn body; \
    } \
} while(0);

#ifndef discard_const
#define discard_const(ptr) ((void *)((uintptr_t)(ptr)))
#endif

#ifndef NULL
#define NULL 0
#endif

#define ZERO_STRUCT(x) memset((char *)&(x), 0, sizeof(x))

#define EOK 0

#define SSSD_MAIN_OPTS SSSD_DEBUG_OPTS

#define FLAGS_NONE 0x0000
#define FLAGS_DAEMON 0x0001
#define FLAGS_INTERACTIVE 0x0002
#define FLAGS_PID_FILE 0x0004

struct main_context {
    struct tevent_context *event_ctx;
    struct confdb_ctx *confdb_ctx;
};

#include "util/dlinklist.h"

/* from server.c */
int server_setup(const char *name, int flags,
                 struct main_context **main_ctx);
void server_loop(struct main_context *main_ctx);

/* from signal.c */
#include <signal.h>
void BlockSignals(bool block, int signum);
void (*CatchSignal(int signum,void (*handler)(int )))(int);
void CatchChild(void);
void CatchChildLeaveStatus(void);

/* from memory.c */
TALLOC_CTX *sssd_mem_takeover(TALLOC_CTX *mem_ctx,
                              void *ptr,
                              int (*destructor)(void **));

/* from usertools.c */
char *get_username_from_uid(TALLOC_CTX *mem_ctx, uid_t uid);

#endif /* __SSSD_UTIL_H__ */
