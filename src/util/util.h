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
#include <arpa/inet.h>
#include <netinet/in.h>

#include <talloc.h>
#include <tevent.h>
#include <ldb.h>
#include <dhash.h>

#include "confdb/confdb.h"
#include "util/atomic_io.h"
#include "util/util_errors.h"
#include "util/util_safealign.h"
#include "util/sss_format.h"

#define _(STRING) gettext (STRING)

#define ENUM_INDICATOR "*"

#define CLEAR_MC_FLAG "clear_mc_flag"

#ifdef HAVE_FUNCTION_ATTRIBUTE_FORMAT
#define SSS_ATTRIBUTE_PRINTF(a1, a2) __attribute__ ((format (printf, a1, a2)))
#else
#define SSS_ATTRIBUTE_PRINTF(a1, a2)
#endif

extern const char *debug_prg_name;
extern int debug_level;
extern int debug_timestamps;
extern int debug_microseconds;
extern int debug_to_file;
extern int debug_to_stderr;
extern const char *debug_log_file;
void debug_fn(const char *file,
              long line,
              const char *function,
              int level,
              const char *format, ...) SSS_ATTRIBUTE_PRINTF(5,6);
int debug_convert_old_level(int old_level);
errno_t set_debug_file_from_fd(const int fd);

#define SSS_DOM_ENV           "_SSS_DOM"

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
        {"debug-to-stderr", 0, POPT_ARG_NONE | POPT_ARGFLAG_DOC_HIDDEN, &debug_to_stderr, 0, \
         _("Send the debug output to stderr directly."), NULL }, \
        {"debug-timestamps", 0, POPT_ARG_INT, &debug_timestamps, 0, \
         _("Add debug timestamps"), NULL}, \
         {"debug-microseconds", 0, POPT_ARG_INT, &debug_microseconds, 0, \
          _("Show timestamps with microseconds"), NULL},

/** \def DEBUG(level, format, ...)
    \brief macro to generate debug messages

    \param level the debug level, please use one of the SSSDBG_* macros
    \param format the debug message format string, should result in a
                  newline-terminated message
    \param ... the debug message format arguments
*/
#define DEBUG(level, format, ...) do { \
    int __debug_macro_level = level; \
    if (DEBUG_IS_SET(__debug_macro_level)) { \
        debug_fn(__FILE__, __LINE__, __FUNCTION__, \
                 __debug_macro_level, \
                 format, ##__VA_ARGS__); \
    } \
} while (0)

/** \def DEBUG_IS_SET(level)
    \brief checks whether level is set in debug_level

    \param level the debug level, please use one of the SSSDBG*_ macros
*/
#define DEBUG_IS_SET(level) (debug_level & (level) || \
                            (debug_level == SSSDBG_UNRESOLVED && \
                                            (level & (SSSDBG_FATAL_FAILURE | \
                                                      SSSDBG_CRIT_FAILURE))))

#define DEBUG_INIT(dbg_lvl) do { \
    if (dbg_lvl != SSSDBG_INVALID) { \
        debug_level = debug_convert_old_level(dbg_lvl); \
    } else { \
        debug_level = SSSDBG_UNRESOLVED; \
    } \
\
    talloc_set_log_fn(talloc_log_fn); \
} while (0)

/* CLI tools shall debug to stderr even when SSSD was compiled with journald
 * support
 */
#define DEBUG_CLI_INIT(dbg_lvl) do { \
    DEBUG_INIT(dbg_lvl);             \
    debug_to_stderr = 1;             \
} while (0)

#define PRINT(fmt, ...) fprintf(stdout, gettext(fmt), ##__VA_ARGS__)
#define ERROR(fmt, ...) fprintf(stderr, gettext(fmt), ##__VA_ARGS__)

#ifndef discard_const
#define discard_const(ptr) ((void *)((uintptr_t)(ptr)))
#endif

#ifndef NULL
#define NULL 0
#endif

#define ZERO_STRUCT(x) memset((char *)&(x), 0, sizeof(x))

#define SSSD_MAIN_OPTS SSSD_DEBUG_OPTS

#define FLAGS_NONE 0x0000
#define FLAGS_DAEMON 0x0001
#define FLAGS_INTERACTIVE 0x0002
#define FLAGS_PID_FILE 0x0004

#ifndef talloc_zfree
#define talloc_zfree(ptr) do { talloc_free(discard_const(ptr)); ptr = NULL; } while(0)
#endif

#ifndef discard_const_p
#if defined(__intptr_t_defined) || defined(HAVE_INTPTR_T)
# define discard_const_p(type, ptr) ((type *)((intptr_t)(ptr)))
#else
# define discard_const_p(type, ptr) ((type *)(ptr))
#endif
#endif

#define TEVENT_REQ_RETURN_ON_ERROR(req) do { \
    enum tevent_req_state TRROEstate; \
    uint64_t TRROEerr; \
    \
    if (tevent_req_is_error(req, &TRROEstate, &TRROEerr)) { \
        if (TRROEstate == TEVENT_REQ_USER_ERROR) { \
            return TRROEerr; \
        } \
        return ERR_INTERNAL; \
    } \
} while (0)

#define OUT_OF_ID_RANGE(id, min, max) \
    (id == 0 || (min && (id < min)) || (max && (id > max)))

#include "util/dlinklist.h"

/* From debug.c */
void ldb_debug_messages(void *context, enum ldb_debug_level level,
                        const char *fmt, va_list ap);
int open_debug_file_ex(const char *filename, FILE **filep, bool want_cloexec);
int open_debug_file(void);
int rotate_debug_files(void);
void talloc_log_fn(const char *msg);

/* From sss_log.c */
#define SSS_LOG_EMERG   0   /* system is unusable */
#define SSS_LOG_ALERT   1   /* action must be taken immediately */
#define SSS_LOG_CRIT    2   /* critical conditions */
#define SSS_LOG_ERR     3   /* error conditions */
#define SSS_LOG_WARNING 4   /* warning conditions */
#define SSS_LOG_NOTICE  5   /* normal but significant condition */
#define SSS_LOG_INFO    6   /* informational */
#define SSS_LOG_DEBUG   7   /* debug-level messages */

void sss_log(int priority, const char *format, ...) SSS_ATTRIBUTE_PRINTF(2, 3);
void sss_log_ext(int priority, int facility, const char *format, ...) SSS_ATTRIBUTE_PRINTF(3, 4);

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
void orderly_shutdown(int status);

/* from signal.c */
#include <signal.h>
void BlockSignals(bool block, int signum);
void (*CatchSignal(int signum,void (*handler)(int )))(int);

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

/* initialize sss_names_ctx directly from arguments */
int sss_names_init_from_args(TALLOC_CTX *mem_ctx,
                             const char *re_pattern,
                             const char *fq_fmt,
                             struct sss_names_ctx **out);

/* initialize sss_names_ctx from domain configuration */
int sss_names_init(TALLOC_CTX *mem_ctx,
                   struct confdb_ctx *cdb,
                   const char *domain,
                   struct sss_names_ctx **out);

int sss_parse_name(TALLOC_CTX *memctx,
                   struct sss_names_ctx *snctx,
                   const char *orig, char **_domain, char **_name);

int sss_parse_name_const(TALLOC_CTX *memctx,
                         struct sss_names_ctx *snctx, const char *orig,
                         const char **_domain, const char **_name);

int sss_parse_name_for_domains(TALLOC_CTX *memctx,
                               struct sss_domain_info *domains,
                               const char *default_domain,
                               const char *orig, char **domain, char **name);

char *
sss_get_cased_name(TALLOC_CTX *mem_ctx, const char *orig_name,
                   bool case_sensitive);

errno_t
sss_get_cased_name_list(TALLOC_CTX *mem_ctx, const char * const *orig,
                        bool case_sensitive, const char ***_cased);

/* Return fully-qualified name according to the fq_fmt. The name is allocated using
 * talloc on top of mem_ctx
 */
char *
sss_tc_fqname(TALLOC_CTX *mem_ctx, struct sss_names_ctx *nctx,
              struct sss_domain_info *domain, const char *name);

/* Return fully-qualified name according to the fq_fmt. The name is allocated using
 * talloc on top of mem_ctx. In contrast to sss_tc_fqname() sss_tc_fqname2()
 * expects the domain and flat domain name as separate arguments.
 */
char *
sss_tc_fqname2(TALLOC_CTX *mem_ctx, struct sss_names_ctx *nctx,
               const char *dom_name, const char *flat_dom_name,
               const char *name);

/* Return fully-qualified name formatted according to the fq_fmt. The buffer in "str" is
 * "size" bytes long. Returns the number of bytes written on success or a negative
 * value of failure.
 *
 * Pass a zero size to calculate the length that would be needed by the fully-qualified
 * name.
 */
int
sss_fqname(char *str, size_t size, struct sss_names_ctx *nctx,
           struct sss_domain_info *domain, const char *name);

/* Subdomains use fully qualified names in the cache while primary domains use
 * just the name. Return either of these for a specified domain or subdomain
 */
char *
sss_get_domain_name(TALLOC_CTX *mem_ctx, const char *orig_name,
                    struct sss_domain_info *dom);

/* from backup-file.c */
int backup_file(const char *src, int dbglvl);

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
errno_t check_file(const char *filename,
                   uid_t uid, gid_t gid, mode_t mode, mode_t mask,
                   struct stat *caller_stat_buf, bool follow_symlink);

/* check_fd()
 * Verify that an open file descriptor has certain permissions and/or
 * is of a certain file type. This function CANNOT detect symlinks,
 * as the file is already open and symlinks have been traversed. This
 * is the safer way to perform file checks and should be preferred
 * over check_file for nearly all situations.
 */
errno_t check_fd(int fd, uid_t uid, gid_t gid,
                 mode_t mode, mode_t mask,
                 struct stat *caller_stat_buf);

/* check_and_open_readonly()
 * Utility function to open a file and verify that it has certain
 * permissions and is of a certain file type. This function wraps
 * check_fd(), and is considered race-condition safe.
 */
errno_t check_and_open_readonly(const char *filename, int *fd,
                                uid_t uid, gid_t gid,
                                mode_t mode, mode_t mask);

/* from util.c */
#define SSS_NO_LINKLOCAL 0x01
#define SSS_NO_LOOPBACK 0x02
#define SSS_NO_MULTICAST 0x04
#define SSS_NO_BROADCAST 0x08

#define SSS_NO_SPECIAL \
        (SSS_NO_LINKLOCAL|SSS_NO_LOOPBACK|SSS_NO_MULTICAST|SSS_NO_BROADCAST)

/* These two functions accept addr in network order */
bool check_ipv4_addr(struct in_addr *addr, uint8_t check);
bool check_ipv6_addr(struct in6_addr *addr, uint8_t check);

const char * const * get_known_services(void);

int split_on_separator(TALLOC_CTX *mem_ctx, const char *str,
                       const char sep, bool trim, bool skip_empty,
                       char ***_list, int *size);

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

errno_t sss_filter_sanitize_for_dom(TALLOC_CTX *mem_ctx,
                                    const char *input,
                                    struct sss_domain_info *dom,
                                    char **sanitized,
                                    char **lc_sanitized);

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

/**
 * @brief Safely zero a segment of memory,
 *        prevents the compiler from optimizing out
 *
 * @param data   The address of buffer to wipe
 * @param size   Size of the buffer
 */
void safezero(void *data, size_t size);

int domain_to_basedn(TALLOC_CTX *memctx, const char *domain, char **basedn);

bool is_host_in_domain(const char *host, const char *domain);

/* from nscd.c */
enum nscd_db {
    NSCD_DB_PASSWD,
    NSCD_DB_GROUP
};

int flush_nscd_cache(enum nscd_db flush_db);

errno_t sss_nscd_parse_conf(const char *conf_path);

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

/* from domain_info.c */
struct sss_domain_info *get_domains_head(struct sss_domain_info *domain);

struct sss_domain_info *get_next_domain(struct sss_domain_info *domain,
                                        bool descend);
struct sss_domain_info *find_subdomain_by_name(struct sss_domain_info *domain,
                                               const char *name,
                                               bool match_any);
struct sss_domain_info *find_subdomain_by_sid(struct sss_domain_info *domain,
                                              const char *sid);
struct sss_domain_info *
find_subdomain_by_object_name(struct sss_domain_info *domain,
                              const char *object_name);

bool subdomain_enumerates(struct sss_domain_info *parent,
                          const char *sd_name);

struct sss_domain_info *new_subdomain(TALLOC_CTX *mem_ctx,
                                      struct sss_domain_info *parent,
                                      const char *name,
                                      const char *realm,
                                      const char *flat_name,
                                      const char *id,
                                      bool mpg,
                                      bool enumerate,
                                      const char *forest);

errno_t sssd_domain_init(TALLOC_CTX *mem_ctx,
                         struct confdb_ctx *cdb,
                         const char *domain_name,
                         const char *db_path,
                         struct sss_domain_info **_domain);

#define IS_SUBDOMAIN(dom) ((dom)->parent != NULL)

errno_t sss_write_domain_mappings(struct sss_domain_info *domain,
                                  bool add_capaths);

/* from util_lock.c */
errno_t sss_br_lock_file(int fd, size_t start, size_t len,
                         int num_tries, useconds_t wait);
#include "io.h"

#ifdef HAVE_PAC_RESPONDER
#define BUILD_WITH_PAC_RESPONDER true
#else
#define BUILD_WITH_PAC_RESPONDER false
#endif

/* from well_known_sids.c */
errno_t well_known_sid_to_name(const char *sid, const char **dom,
                               const char **name);

errno_t name_to_well_known_sid(const char *dom, const char *name,
                               const char **sid);

#endif /* __SSSD_UTIL_H__ */
