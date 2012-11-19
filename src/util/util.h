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

#include "config.h"
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>
#include <errno.h>
#include <libintl.h>
#include <limits.h>
#include <locale.h>
#include <time.h>
#include <pcre.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <talloc.h>
#include <tevent.h>
#include <ldb.h>
#include <dhash.h>

#include "util/atomic_io.h"

#ifndef HAVE_ERRNO_T
#define HAVE_ERRNO_T
typedef int errno_t;
#endif

#define _(STRING) gettext (STRING)

#define ENUM_INDICATOR "*"

#define CLEAR_MC_FLAG "clear_mc_flag"

extern const char *debug_prg_name;
extern int debug_level;
extern int debug_timestamps;
extern int debug_microseconds;
extern int debug_to_file;
extern const char *debug_log_file;
void debug_fn(const char *format, ...);
int debug_get_level(int old_level);
int debug_convert_old_level(int old_level);
errno_t set_debug_file_from_fd(const int fd);

#define SSSDBG_FATAL_FAILURE  0x0010   /* level 0 */
#define SSSDBG_CRIT_FAILURE   0x0020   /* level 1 */
#define SSSDBG_OP_FAILURE     0x0040   /* level 2 */
#define SSSDBG_MINOR_FAILURE  0x0080   /* level 3 */
#define SSSDBG_CONF_SETTINGS  0x0100   /* level 4 */
#define SSSDBG_FUNC_DATA      0x0200   /* level 5 */
#define SSSDBG_TRACE_FUNC     0x0400   /* level 6 */
#define SSSDBG_TRACE_LIBS     0x1000   /* level 7 */
#define SSSDBG_TRACE_INTERNAL 0x2000   /* level 8 */
#define SSSDBG_TRACE_ALL      0x4000   /* level 9 */
#define SSSDBG_IMPORTANT_INFO SSSDBG_OP_FAILURE

#define SSSDBG_INVALID        -1
#define SSSDBG_UNRESOLVED     0
#define SSSDBG_MASK_ALL       0xFFF0   /* enable all debug levels */
#define SSSDBG_DEFAULT        SSSDBG_FATAL_FAILURE

#define SSSDBG_TIMESTAMP_UNRESOLVED   -1
#define SSSDBG_TIMESTAMP_DEFAULT       1

#define SSSDBG_MICROSECONDS_UNRESOLVED   -1
#define SSSDBG_MICROSECONDS_DEFAULT       0

#define SSSD_DEBUG_OPTS \
        {"debug-level", 'd', POPT_ARG_INT, &debug_level, 0, \
         _("Debug level"), NULL}, \
        {"debug-to-files", 'f', POPT_ARG_NONE, &debug_to_file, 0, \
         _("Send the debug output to files instead of stderr"), NULL }, \
        {"debug-timestamps", 0, POPT_ARG_INT, &debug_timestamps, 0, \
         _("Add debug timestamps"), NULL}, \
         {"debug-microseconds", 0, POPT_ARG_INT, &debug_microseconds, 0, \
          _("Show timestamps with microseconds"), NULL},

/** \def DEBUG(level, body)
    \brief macro to generate debug messages

    \param level the debug level, please use one of the SSSDBG_* macros
      Old format:
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
    int __debug_macro_newlevel = debug_get_level(level); \
    if (DEBUG_IS_SET(__debug_macro_newlevel)) { \
        if (debug_timestamps) { \
            struct timeval __debug_macro_tv; \
            struct tm *__debug_macro_tm; \
            char __debug_macro_datetime[20]; \
            int __debug_macro_year; \
            gettimeofday(&__debug_macro_tv, NULL); \
            __debug_macro_tm = localtime(&__debug_macro_tv.tv_sec); \
            __debug_macro_year = __debug_macro_tm->tm_year + 1900; \
            /* get date time without year */ \
            memcpy(__debug_macro_datetime, ctime(&__debug_macro_tv.tv_sec), 19); \
            __debug_macro_datetime[19] = '\0'; \
            if (debug_microseconds) { \
                debug_fn("(%s:%.6d %d) [%s] [%s] (%#.4x): ", \
                         __debug_macro_datetime, __debug_macro_tv.tv_usec, \
                         __debug_macro_year, debug_prg_name, \
                         __FUNCTION__, __debug_macro_newlevel); \
            } else { \
                debug_fn("(%s %d) [%s] [%s] (%#.4x): ", \
                         __debug_macro_datetime, __debug_macro_year, \
                         debug_prg_name, __FUNCTION__, __debug_macro_newlevel); \
            } \
        } else { \
            debug_fn("[%s] [%s] (%#.4x): ", \
                     debug_prg_name, __FUNCTION__, __debug_macro_newlevel); \
        } \
        debug_fn body; \
    } \
} while(0)

/** \def DEBUG_MSG(level, function, message)
    \brief macro to generate debug messages with message from variable

    \param level the debug level, please use one of the SSSDBG_* macros

    \param function name of the function where DEBUG_MSG is called

    \param message message to be send (should not end with \n)
*/
#define DEBUG_MSG(level, function, message) do { \
    int __debug_macro_newlevel = debug_get_level(level); \
    if (DEBUG_IS_SET(__debug_macro_newlevel)) { \
        if (debug_timestamps) { \
            struct timeval __debug_macro_tv; \
            struct tm *__debug_macro_tm; \
            char __debug_macro_datetime[20]; \
            int __debug_macro_year; \
            gettimeofday(&__debug_macro_tv, NULL); \
            __debug_macro_tm = localtime(&__debug_macro_tv.tv_sec); \
            __debug_macro_year = __debug_macro_tm->tm_year + 1900; \
            /* get date time without year */ \
            memcpy(__debug_macro_datetime, ctime(&__debug_macro_tv.tv_sec), 19); \
            __debug_macro_datetime[19] = '\0'; \
            if (debug_microseconds) { \
                debug_fn("(%s:%.6d %d) [%s] [%s] (%#.4x): %s\n", \
                         __debug_macro_datetime, __debug_macro_tv.tv_usec, \
                         __debug_macro_year, debug_prg_name, \
                         function, __debug_macro_newlevel, message); \
            } else { \
                debug_fn("(%s %d) [%s] [%s] (%#.4x): %s\n", \
                         __debug_macro_datetime, __debug_macro_year, \
                         debug_prg_name, function, __debug_macro_newlevel, \
                         message); \
            } \
        } else { \
            debug_fn("[%s] [%s] (%#.4x): %s\n", \
                     debug_prg_name, function, __debug_macro_newlevel, message); \
        } \
    } \
} while(0)

/** \def DEBUG_IS_SET(level)
    \brief checks whether level (must be in new format) is set in debug_level

    \param level the debug level, please use one of the SSSDBG*_ macros
*/
#define DEBUG_IS_SET(level) (debug_level & (level) || \
                            (debug_level == SSSDBG_UNRESOLVED && \
                                            (level & (SSSDBG_FATAL_FAILURE | \
                                                      SSSDBG_CRIT_FAILURE))))

#define CONVERT_AND_SET_DEBUG_LEVEL(new_value) debug_level = ( \
    ((new_value) != SSSDBG_INVALID) \
    ? debug_convert_old_level(new_value) \
    : SSSDBG_UNRESOLVED /* Debug level should be loaded from config file. */ \
);

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

#define SIZE_T_MAX ((size_t) -1)

#define SIZE_T_OVERFLOW(current, add) \
                        (((size_t)(add)) > (SIZE_T_MAX - ((size_t)(current))))

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

#define SAFEALIGN_COPY_INT64(dest, src, pctr) \
    safealign_memcpy(dest, src, sizeof(int64_t), pctr)

#define SAFEALIGN_SET_INT64(dest, value, pctr) \
    SAFEALIGN_SET_VALUE(dest, value, int64_t, pctr)

#define SAFEALIGN_COPY_UINT32(dest, src, pctr) \
    safealign_memcpy(dest, src, sizeof(uint32_t), pctr)

#define SAFEALIGN_SET_UINT32(dest, value, pctr) \
    SAFEALIGN_SET_VALUE(dest, value, uint32_t, pctr)

#define SAFEALIGN_COPY_INT32(dest, src, pctr) \
    safealign_memcpy(dest, src, sizeof(int32_t), pctr)

#define SAFEALIGN_SET_INT32(dest, value, pctr) \
    SAFEALIGN_SET_VALUE(dest, value, int32_t, pctr)

#define SAFEALIGN_COPY_UINT16(dest, src, pctr) \
    safealign_memcpy(dest, src, sizeof(uint16_t), pctr)

#define SAFEALIGN_SET_UINT16(dest, value, pctr) \
    SAFEALIGN_SET_VALUE(dest, value, uint16_t, pctr)

#define SAFEALIGN_COPY_UINT32_CHECK(dest, src, len, pctr) do { \
    if ((*(pctr) + sizeof(uint32_t)) > (len) || \
        SIZE_T_OVERFLOW(*(pctr), sizeof(uint32_t))) return EINVAL; \
    safealign_memcpy(dest, src, sizeof(uint32_t), pctr); \
} while(0)

#define SAFEALIGN_COPY_INT32_CHECK(dest, src, len, pctr) do { \
    if ((*(pctr) + sizeof(int32_t)) > (len) || \
        SIZE_T_OVERFLOW(*(pctr), sizeof(int32_t))) return EINVAL; \
    safealign_memcpy(dest, src, sizeof(int32_t), pctr); \
} while(0)

#define SAFEALIGN_COPY_UINT16_CHECK(dest, src, len, pctr) do { \
    if ((*(pctr) + sizeof(uint16_t)) > (len) || \
        SIZE_T_OVERFLOW(*(pctr), sizeof(uint16_t))) return EINVAL; \
    safealign_memcpy(dest, src, sizeof(uint16_t), pctr); \
} while(0)

#include "util/dlinklist.h"

/* From debug.c */
void ldb_debug_messages(void *context, enum ldb_debug_level level,
                        const char *fmt, va_list ap);
int open_debug_file_ex(const char *filename, FILE **filep);
int open_debug_file(void);
int rotate_debug_files(void);

/* From sss_log.c */
#define SSS_LOG_EMERG   0   /* system is unusable */
#define SSS_LOG_ALERT   1   /* action must be taken immediately */
#define SSS_LOG_CRIT    2   /* critical conditions */
#define SSS_LOG_ERR     3   /* error conditions */
#define SSS_LOG_WARNING 4   /* warning conditions */
#define SSS_LOG_NOTICE  5   /* normal but significant condition */
#define SSS_LOG_INFO    6   /* informational */
#define SSS_LOG_DEBUG   7   /* debug-level messages */

void sss_log(int priority, const char *format, ...);

/* from server.c */
struct main_context {
    struct tevent_context *event_ctx;
    struct confdb_ctx *confdb_ctx;
    pid_t parent_pid;
};

int die_if_parent_died(void);
int pidfile(const char *path, const char *name);
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

char *get_uppercase_realm(TALLOC_CTX *memctx, const char *name);

struct sss_names_ctx {
    char *re_pattern;
    char *fq_fmt;

    pcre *re;
};

int sss_names_init(TALLOC_CTX *mem_ctx,
                   struct confdb_ctx *cdb,
                   const char *domain,
                   struct sss_names_ctx **out);

int sss_parse_name(TALLOC_CTX *memctx,
                   struct sss_names_ctx *snctx,
                   const char *orig, char **domain, char **name);

char *
sss_get_cased_name(TALLOC_CTX *mem_ctx, const char *orig_name,
                   bool case_sensitive);

errno_t
sss_get_cased_name_list(TALLOC_CTX *mem_ctx, const char * const *orig,
                        bool case_sensitive, const char ***_cased);

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
                   struct stat *caller_stat_buf, bool follow_symlink);

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

errno_t sss_hash_create(TALLOC_CTX *mem_ctx,
                        unsigned long count,
                        hash_table_t **tbl);

errno_t sss_hash_create_ex(TALLOC_CTX *mem_ctx,
                           unsigned long count,
                           hash_table_t **tbl,
                           unsigned int directory_bits,
                           unsigned int segment_bits,
                           unsigned long min_load_factor,
                           unsigned long max_load_factor,
                           hash_delete_callback *delete_callback,
                           void *delete_private_data);

/* Copy a NULL-terminated string list
 * Returns NULL on out of memory error or invalid input
 */
char **dup_string_list(TALLOC_CTX *memctx, const char **str_list);

/* Take two string lists (terminated on a NULL char*)
 * and return up to three arrays of strings based on
 * shared ownership.
 *
 * Pass NULL to any return type you don't care about
 */
errno_t diff_string_lists(TALLOC_CTX *memctx,
                          char **string1,
                          char **string2,
                          char ***string1_only,
                          char ***string2_only,
                          char ***both_strings);

/* Sanitize an input string (e.g. a username) for use in
 * an LDAP/LDB filter
 * Returns a newly-constructed string attached to mem_ctx
 * It will fail only on an out of memory condition, where it
 * will return ENOMEM.
 */
errno_t sss_filter_sanitize(TALLOC_CTX *mem_ctx,
                            const char *input,
                            char **sanitized);

char *
sss_escape_ip_address(TALLOC_CTX *mem_ctx, int family, const char *addr);

/* This function only removes first and last
 * character if the first character was '['.
 *
 * NOTE: This means, that ipv6addr must NOT be followed
 * by port number.
 */
errno_t
remove_ipv6_brackets(char *ipv6addr);


errno_t add_string_to_list(TALLOC_CTX *mem_ctx, const char *string,
                           char ***list_p);

bool string_in_list(const char *string, char **list, bool case_sensitive);

/* from sss_tc_utf8.c */
char *
sss_tc_utf8_str_tolower(TALLOC_CTX *mem_ctx, const char *s);
uint8_t *
sss_tc_utf8_tolower(TALLOC_CTX *mem_ctx, const uint8_t *s, size_t len, size_t *_nlen);
bool sss_string_equal(bool cs, const char *s1, const char *s2);

/* len includes terminating '\0' */
struct sized_string {
    const char *str;
    size_t len;
};

void to_sized_string(struct sized_string *out, const char *in);

/* form domain_info.c */
struct sss_domain_info *new_subdomain(TALLOC_CTX *mem_ctx,
                                      struct sss_domain_info *parent,
                                      const char *name,
                                      const char *flat_name,
                                      const char *id);
struct sss_domain_info *copy_subdomain(TALLOC_CTX *mem_ctx,
                                       struct sss_domain_info *subdomain);

/* from util_lock.c */
errno_t sss_br_lock_file(int fd, size_t start, size_t len,
                         int num_tries, useconds_t wait);

/* Endianness-compatibility for systems running older versions of glibc */

#ifndef le32toh
#include <byteswap.h>

/* Copied from endian.h on glibc 2.15 */
#ifdef __USE_BSD
/* Conversion interfaces.  */
# if __BYTE_ORDER == __LITTLE_ENDIAN
#  define le32toh(x) (x)
#  define htole32(x) (x)
# else
#  define le32toh(x) __bswap_32 (x)
#  define htole32(x) __bswap_32 (x)
# endif
#endif /* __USE_BSD */

#endif /* le32toh */

#ifdef HAVE_PAC_RESPONDER
#define BUILD_WITH_PAC_RESPONDER true
#else
#define BUILD_WITH_PAC_RESPONDER false
#endif

#endif /* __SSSD_UTIL_H__ */
