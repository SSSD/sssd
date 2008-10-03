#ifndef __SSSD_UTIL_H__
#define __SSSD_UTIL_H__

#include <stdbool.h>

#define DEBUG(level, body)
#define DEBUGADD(level, body)

#ifndef discard_const
#define discard_const(ptr) ((void *)((uintptr_t)(ptr)))
#endif

#ifndef NULL
#define NULL 0
#endif

#define ZERO_STRUCT(x) memset((char *)&(x), 0, sizeof(x))

#define PID_DIR "/var/run/sssd"

#define RES_SUCCESS 0
#define RES_ERROR 1
#define RES_NOMEM 2
#define RES_INVALID_DATA 3

#include "util/dlinklist.h"

/* from become_daemon.c */
void become_daemon(bool Fork);

/* from signal.c */
#include <signal.h>
void BlockSignals(bool block, int signum);
void (*CatchSignal(int signum,void (*handler)(int )))(int);
void CatchChild(void);
void CatchChildLeaveStatus(void);

#endif /* __SSSD_UTIL_H__ */
