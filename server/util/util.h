#ifndef __SSSD_UTIL_H__
#define __SSSD_UTIL_H__

#include <stdio.h>
#include <stdbool.h>
#include "replace.h"
#include "talloc.h"

extern const char *debug_prg_name;
extern int debug_level;
void debug_fn(const char *format, ...);

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

#define PID_DIR "/var/run/sssd"

#define EOK 0

#include "util/dlinklist.h"

/* from become_daemon.c */
void become_daemon(bool Fork);
int pidfile(const char *path, const char *name);

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

#endif /* __SSSD_UTIL_H__ */
