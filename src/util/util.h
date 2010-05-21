/*
    Authors:
        Simo Sorce <ssorce@redhat.com>

    Copyright (C) 2009 Red Hat

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef __SSSD_UTIL_H__
#define __SSSD_UTIL_H__

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <libintl.h>
#include <limits.h>
#include <locale.h>
#include <time.h>
#include <pcre.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "config.h"

#include <talloc.h>
#include <tevent.h>
#include <ldb.h>

#ifndef HAVE_ERRNO_T
#define HAVE_ERRNO_T
typedef int errno_t;
#endif

#define _(STRING) gettext (STRING)

extern const char *debug_prg_name;
extern int debug_level;
extern int debug_timestamps;
extern int debug_to_file;
extern const char *debug_log_file;
void debug_fn(const char *format, ...);
errno_t set_debug_file_from_fd(const int fd);

#define SSSD_DEBUG_OPTS \
        {"debug-level", 'd', POPT_ARG_INT, &debug_level, 0, \
         _("Debug level"), NULL}, \
        {"debug-to-files", 'f', POPT_ARG_NONE, &debug_to_file, 0, \
         _("Send the debug output to files instead of stderr"), NULL }, \
        {"debug-timestamps", 0, POPT_ARG_INT, &debug_timestamps, 0, \
         _("Add debug timestamps"), NULL},

/** \def DEBUG(level, body)
    \brief macro to generate debug messages

    \param level the debug level, please respect the following guidelines:
      - 1 is for critical errors users may find it difficult to understand but
        are still quite clear
      - 2-4 is for stuff developers are interested in in general, but
        shouldn't fill the screen with useless low level verbose stuff
      - 5-6 is for errors you may want to track, but only if you explicitly
        looking for additional clues
      - 7-10 is for informational stuff

    \param body the debug message you want to send, should end with \n
*/
#define DEBUG(level, body) do { \
    if (level <= debug_level) { \
        if (debug_timestamps) { \
            time_t rightnow = time(NULL); \
            char stamp[25]; \
            memcpy(stamp, ctime(&rightnow), 24); \
            stamp[24] = '\0'; \
            debug_fn("(%s) [%s] [%s] (%d): ", \
                     stamp, debug_prg_name, __FUNCTION__, level); \
        } else { \
            debug_fn("[%s] [%s] (%d): ", \
                     debug_prg_name, __FUNCTION__, level); \
        } \
        debug_fn body; \
    } \
} while(0);

#define PRINT(fmt, ...) fprintf(stdout, gettext(fmt), ##__VA_ARGS__)
#define ERROR(fmt, ...) fprintf(stderr, gettext(fmt), ##__VA_ARGS__)

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

#ifndef talloc_zfree
#define talloc_zfree(ptr) do { \
        TALLOC_CTX *_tmp_ctx = ptr; \
        ptr = NULL; \
        talloc_free(_tmp_ctx); \
    } while(0)
#endif

#ifndef discard_const_p
#if defined(__intptr_t_defined) || defined(HAVE_INTPTR_T)
# define discard_const_p(type, ptr) ((type *)((intptr_t)(ptr)))
#else
# define discard_const_p(type, ptr) ((type *)(ptr))
#endif
#endif

/* TODO: remove later
 * These functions are available in the latest tevent and are the ones that
 * should be used as tevent_req is rightfully opaque there */
#ifndef tevent_req_data
#define tevent_req_data(req, type) ((type *)req->private_state)
#define tevent_req_set_callback(req, func, data) \
    do { req->async.fn = func; req->async.private_data = data; } while(0)
#define tevent_req_callback_data(req, type) ((type *)req->async.private_data)
#define tevent_req_notify_callback(req) \
    do { \
        if (req->async.fn != NULL) { \
            req->async.fn(req); \
        } \
    } while(0)

/* noop */
#define tevent_loop_allow_nesting(x)
#endif

#define TEVENT_REQ_RETURN_ON_ERROR(req) do { \
    enum tevent_req_state TRROEstate; \
    uint64_t TRROEerr; \
    \
    if (tevent_req_is_error(req, &TRROEstate, &TRROEerr)) { \
        if (TRROEstate == TEVENT_REQ_USER_ERROR) { \
            return TRROEerr; \
        } \
        return EIO; \
    } \
} while (0)

#define OUT_OF_ID_RANGE(id, min, max) \
    (id == 0 || (min && (id < min)) || (max && (id > max)))

static inline void
safealign_memcpy(void *dest, const void *src, size_t n, size_t *counter)
{
    memcpy(dest, src, n);
    if (counter) {
        *counter += n;
    }
}

#define SAFEALIGN_SET_VALUE(dest, value, type, pctr) do { \
    type CV_MACRO_val = (type)(value); \
    safealign_memcpy(dest, &CV_MACRO_val, sizeof(type), pctr); \
} while(0)

#define SAFEALIGN_COPY_UINT32(dest, src, pctr) \
    safealign_memcpy(dest, src, sizeof(uint32_t), pctr)

#define SAFEALIGN_SET_UINT32(dest, value, pctr) \
    SAFEALIGN_SET_VALUE(dest, value, uint32_t, pctr)

#define SAFEALIGN_COPY_INT32(dest, src, pctr) \
    safealign_memcpy(dest, src, sizeof(int32_t), pctr)

#define SAFEALIGN_SET_INT32(dest, value, pctr) \
    SAFEALIGN_SET_VALUE(dest, value, int32_t, pctr)

#define SAFEALIGN_COPY_UINT32_CHECK(dest, src, len, pctr) do { \
    if ((*(pctr) + sizeof(uint32_t)) > (len)) return EINVAL; \
    safealign_memcpy(dest, src, sizeof(uint32_t), pctr); \
} while(0)

#define SAFEALIGN_COPY_INT32_CHECK(dest, src, len, pctr) do { \
    if ((*(pctr) + sizeof(int32_t)) > (len)) return EINVAL; \
    safealign_memcpy(dest, src, sizeof(int32_t), pctr); \
} while(0)

#include "util/dlinklist.h"

/* From debug.c */
void ldb_debug_messages(void *context, enum ldb_debug_level level,
                        const char *fmt, va_list ap);
int open_debug_file_ex(const char *filename, FILE **filep);
int open_debug_file(void);
int rotate_debug_files(void);

/* from server.c */
struct main_context {
    struct tevent_context *event_ctx;
    struct confdb_ctx *confdb_ctx;
};

int die_if_parent_died(void);
int server_setup(const char *name, int flags,
                 const char *conf_entry,
                 struct main_context **main_ctx);
void server_loop(struct main_context *main_ctx);
void sig_term(int sig);

/* from signal.c */
#include <signal.h>
void BlockSignals(bool block, int signum);
void (*CatchSignal(int signum,void (*handler)(int )))(int);
void CatchChild(void);
void CatchChildLeaveStatus(void);

/* from memory.c */
typedef int (void_destructor_fn_t)(void *);

struct mem_holder {
    void *mem;
    void_destructor_fn_t *fn;
};

void *sss_mem_attach(TALLOC_CTX *mem_ctx,
                     void *ptr,
                     void_destructor_fn_t *fn);

int password_destructor(void *memctx);

/* from usertools.c */
char *get_username_from_uid(TALLOC_CTX *mem_ctx, uid_t uid);

struct sss_names_ctx {
    char *re_pattern;
    char *fq_fmt;

    pcre *re;
};

int sss_names_init(TALLOC_CTX *mem_ctx,
                   struct confdb_ctx *cdb,
                   struct sss_names_ctx **out);

int sss_parse_name(TALLOC_CTX *memctx,
                   struct sss_names_ctx *snctx,
                   const char *orig, char **domain, char **name);

/* from backup-file.c */
int backup_file(const char *src, int dbglvl);

/* from check_and_open.c */
enum check_file_type {
    CHECK_DONT_CHECK_FILE_TYPE = -1,
    CHECK_REG,
    CHECK_DIR,
    CHECK_CHR,
    CHECK_BLK,
    CHECK_FIFO,
    CHECK_LNK,
    CHECK_SOCK
};

/* check_file()
 * Verify that a file has certain permissions and/or is of a certain
 * file type. This function can be used to determine if a file is a
 * symlink.
 * Warning: use of this function implies a potential race condition
 * Opening a file before or after checking it does NOT guarantee that
 * it is still the same file. Additional checks should be performed
 * on the caller_stat_buf to ensure that it has the same device and
 * inode to minimize impact. Permission changes may have occurred,
 * however.
 */
errno_t check_file(const char *filename, const int uid, const int gid,
                   const int mode, enum check_file_type type,
                   struct stat *caller_stat_buf);

/* check_fd()
 * Verify that an open file descriptor has certain permissions and/or
 * is of a certain file type. This function CANNOT detect symlinks,
 * as the file is already open and symlinks have been traversed. This
 * is the safer way to perform file checks and should be preferred
 * over check_file for nearly all situations.
 */
errno_t check_fd(int fd, const int uid, const int gid,
                 const int mode, enum check_file_type type,
                 struct stat *caller_stat_buf);

/* check_and_open_readonly()
 * Utility function to open a file and verify that it has certain
 * permissions and is of a certain file type. This function wraps
 * check_fd(), and is considered race-condition safe.
 */
errno_t check_and_open_readonly(const char *filename, int *fd, const uid_t uid,
                               const gid_t gid, const mode_t mode,
                               enum check_file_type type);

/* from util.c */
int split_on_separator(TALLOC_CTX *mem_ctx, const char *str,
                       const char sep, bool trim, char ***_list, int *size);

char **parse_args(const char *str);
#endif /* __SSSD_UTIL_H__ */
