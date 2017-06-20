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
#include <libintl.h>
#include <locale.h>
#include <time.h>
#include <pcre.h>
#include <sys/types.h>
#include <sys/stat.h>
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
#include "util/debug.h"

/* name of the monitor server instance */
#define SSSD_PIDFILE PID_PATH"/sssd.pid"
#define MAX_PID_LENGTH 10

#define _(STRING) gettext (STRING)

#define ENUM_INDICATOR "*"

#define CLEAR_MC_FLAG "clear_mc_flag"

/** Default secure umask */
#define SSS_DFL_UMASK 0177

/** Secure mask with executable bit */
#define SSS_DFL_X_UMASK 0077

#ifndef NULL
#define NULL 0
#endif

#define ZERO_STRUCT(x) memset((char *)&(x), 0, sizeof(x))

#define SSSD_MAIN_OPTS SSSD_DEBUG_OPTS

#define SSSD_SERVER_OPTS(uid, gid) \
        {"uid", 0, POPT_ARG_INT, &uid, 0, \
          _("The user ID to run the server as"), NULL}, \
        {"gid", 0, POPT_ARG_INT, &gid, 0, \
          _("The group ID to run the server as"), NULL},

extern int socket_activated;
extern int dbus_activated;

#ifdef HAVE_SYSTEMD
#define SSSD_RESPONDER_OPTS \
        { "socket-activated", 0, POPT_ARG_NONE, &socket_activated, 0, \
          _("Informs that the responder has been socket-activated"), NULL }, \
        { "dbus-activated", 0, POPT_ARG_NONE, &dbus_activated, 0, \
          _("Informs that the responder has been dbus-activated"), NULL },
#else
#define SSSD_RESPONDER_OPTS
#endif

#define FLAGS_NONE 0x0000
#define FLAGS_DAEMON 0x0001
#define FLAGS_INTERACTIVE 0x0002
#define FLAGS_PID_FILE 0x0004
#define FLAGS_GEN_CONF 0x0008
#define FLAGS_NO_WATCHDOG 0x0010

#define PIPE_INIT { -1, -1 }

#define PIPE_FD_CLOSE(fd) do {      \
    if (fd != -1) {                 \
        close(fd);                  \
        fd = -1;                    \
    }                               \
} while(0);

#define PIPE_CLOSE(p) do {          \
    PIPE_FD_CLOSE(p[0]);            \
    PIPE_FD_CLOSE(p[1]);            \
} while(0);

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
    uint64_t TRROEuint64; \
    errno_t TRROEerr; \
    \
    if (tevent_req_is_error(req, &TRROEstate, &TRROEuint64)) { \
        TRROEerr = (errno_t)TRROEuint64; \
        if (TRROEstate == TEVENT_REQ_USER_ERROR) { \
            if (TRROEerr == 0) { \
                return ERR_INTERNAL; \
            } \
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
int chown_debug_file(const char *filename, uid_t uid, gid_t gid);
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

errno_t server_common_rotate_logs(struct confdb_ctx *confdb,
                                  const char *conf_entry);
int die_if_parent_died(void);
int pidfile(const char *path, const char *name);
int server_setup(const char *name, int flags,
                 uid_t uid, gid_t gid,
                 const char *conf_entry,
                 struct main_context **main_ctx);
void server_loop(struct main_context *main_ctx);
void orderly_shutdown(int status);

/* from signal.c */
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

int sss_ad_default_names_ctx(TALLOC_CTX *mem_ctx,
                             struct sss_names_ctx **_out);

int sss_parse_name(TALLOC_CTX *memctx,
                   struct sss_names_ctx *snctx,
                   const char *orig, char **_domain, char **_name);

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


/* Accepts fqname in the format shortname@domname only. */
errno_t sss_parse_internal_fqname(TALLOC_CTX *mem_ctx,
                                  const char *fqname,
                                  char **_shortname,
                                  char **_dom_name);

/* Creates internal fqname in format shortname@domname.
 * The domain portion is lowercased. */
char *sss_create_internal_fqname(TALLOC_CTX *mem_ctx,
                                 const char *shortname,
                                 const char *dom_name);

/* Creates internal fqnames list in format shortname@domname.
 * The domain portion is lowercased. */
char **sss_create_internal_fqname_list(TALLOC_CTX *mem_ctx,
                                       const char * const *shortname_list,
                                       const char *dom_name);

/* Turn fqname into cased shortname with replaced space. */
char *sss_output_name(TALLOC_CTX *mem_ctx,
                      const char *fqname,
                      bool case_sensitive,
                      const char replace_space);

int sss_output_fqname(TALLOC_CTX *mem_ctx,
                      struct sss_domain_info *domain,
                      const char *name,
                      char override_space,
                      char **_output_name);

const char *sss_get_name_from_msg(struct sss_domain_info *domain,
                                  struct ldb_message *msg);

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

errno_t sss_user_by_name_or_uid(const char *input, uid_t *_uid, gid_t *_gid);

int split_on_separator(TALLOC_CTX *mem_ctx, const char *str,
                       const char sep, bool trim, bool skip_empty,
                       char ***_list, int *size);

char **parse_args(const char *str);

struct cert_verify_opts {
    bool do_ocsp;
    bool do_verification;
    char *ocsp_default_responder;
    char *ocsp_default_responder_signing_cert;
};

errno_t parse_cert_verify_opts(TALLOC_CTX *mem_ctx, const char *verify_opts,
                               struct cert_verify_opts **cert_verify_opts);

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

/* Returns true if sudoUser value is a username or a groupname */
bool is_user_or_group_name(const char *sudo_user_value);

/* Returns true if the responder has been socket-activated */
bool is_socket_activated(void);

/* Returns true if the responder has been dbus-activated */
bool is_dbus_activated(void);

/**
 * @brief Add two list of strings
 *
 * Create a new NULL-termintated list of strings by adding two lists together.
 *
 * @param[in] mem_ctx      Talloc memory context for the new list.
 * @param[in] l1           First NULL-termintated list of strings.
 * @param[in] l2           Second NULL-termintated list of strings.
 * @param[in] copy_strings If set to 'true' the list items will be copied
 *                         otherwise only the pointers to the items are
 *                         copied.
 * @param[out] new_list    New NULL-terminated list of strings. Must be freed
 *                         with talloc_free() by the caller. If copy_strings
 *                         is 'true' the new elements will be freed as well.
 */
errno_t add_strings_lists(TALLOC_CTX *mem_ctx, const char **l1, const char **l2,
                          bool copy_strings, char ***_new_list);

/**
 * @brief set file descriptor as nonblocking
 *
 * Set the O_NONBLOCK flag for the input fd
 *
 * @param[in] fd            The file descriptor to set as nonblocking
 *
 * @return                  EOK on success, errno code otherwise
 */
errno_t sss_fd_nonblocking(int fd);

/* Copy a NULL-terminated string list
 * Returns NULL on out of memory error or invalid input
 */
const char **dup_string_list(TALLOC_CTX *memctx, const char **str_list);

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

errno_t sss_filter_sanitize_ex(TALLOC_CTX *mem_ctx,
                               const char *input,
                               char **sanitized,
                               const char *ignore);

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

#define SSS_GND_DESCEND 0x01
#define SSS_GND_INCLUDE_DISABLED 0x02
#define SSS_GND_ALL_DOMAINS (SSS_GND_DESCEND | SSS_GND_INCLUDE_DISABLED)
struct sss_domain_info *get_next_domain(struct sss_domain_info *domain,
                                        uint32_t gnd_flags);
struct sss_domain_info *find_domain_by_name(struct sss_domain_info *domain,
                                            const char *name,
                                            bool match_any);
struct sss_domain_info *find_domain_by_sid(struct sss_domain_info *domain,
                                           const char *sid);
enum sss_domain_state sss_domain_get_state(struct sss_domain_info *dom);
void sss_domain_set_state(struct sss_domain_info *dom,
                          enum sss_domain_state state);
bool is_email_from_domain(const char *email, struct sss_domain_info *dom);
bool sss_domain_is_forest_root(struct sss_domain_info *dom);
const char *sss_domain_type_str(struct sss_domain_info *dom);

struct sss_domain_info*
sss_get_domain_by_sid_ldap_fallback(struct sss_domain_info *domain,
                                    const char* sid);

struct sss_domain_info *
find_domain_by_object_name(struct sss_domain_info *domain,
                           const char *object_name);

bool subdomain_enumerates(struct sss_domain_info *parent,
                          const char *sd_name);

char *subdomain_create_conf_path(TALLOC_CTX *mem_ctx,
                                 struct sss_domain_info *subdomain);

errno_t sssd_domain_init(TALLOC_CTX *mem_ctx,
                         struct confdb_ctx *cdb,
                         const char *domain_name,
                         const char *db_path,
                         struct sss_domain_info **_domain);

void sss_domain_info_set_output_fqnames(struct sss_domain_info *domain,
                                        bool output_fqname);

bool sss_domain_info_get_output_fqnames(struct sss_domain_info *domain);

#define IS_SUBDOMAIN(dom) ((dom)->parent != NULL)

#define DOM_HAS_VIEWS(dom) ((dom)->has_views)

/* the directory domain - realm mappings and other krb5 config snippers are
 * written to */
#define KRB5_MAPPING_DIR PUBCONF_PATH"/krb5.include.d"

errno_t sss_get_domain_mappings_content(TALLOC_CTX *mem_ctx,
                                        struct sss_domain_info *domain,
                                        char **content);

errno_t sss_write_domain_mappings(struct sss_domain_info *domain);

errno_t sss_write_krb5_conf_snippet(const char *path, bool canonicalize);

errno_t get_dom_names(TALLOC_CTX *mem_ctx,
                      struct sss_domain_info *start_dom,
                      char ***_dom_names,
                      int *_dom_names_count);

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

/* from string_utils.c */
char *sss_replace_char(TALLOC_CTX *mem_ctx,
                       const char *in,
                       const char match,
                       const char sub);

char * sss_replace_space(TALLOC_CTX *mem_ctx,
                         const char *orig_name,
                         const char replace_char);
char * sss_reverse_replace_space(TALLOC_CTX *mem_ctx,
                                 const char *orig_name,
                                 const char replace_char);

#define GUID_BIN_LENGTH 16
/* 16 2-digit hex values + 4 dashes + terminating 0 */
#define GUID_STR_BUF_SIZE (2 * GUID_BIN_LENGTH + 4 + 1)

errno_t guid_blob_to_string_buf(const uint8_t *blob, char *str_buf,
                                size_t buf_size);

const char *get_last_x_chars(const char *str, size_t x);

char **concatenate_string_array(TALLOC_CTX *mem_ctx,
                                char **arr1, size_t len1,
                                char **arr2, size_t len2);

/* from become_user.c */
errno_t become_user(uid_t uid, gid_t gid);
struct sss_creds;
errno_t switch_creds(TALLOC_CTX *mem_ctx,
                     uid_t uid, gid_t gid,
                     int num_gids, gid_t *gids,
                     struct sss_creds **saved_creds);
errno_t restore_creds(struct sss_creds *saved_creds);

/* from sss_semanage.c */
/* Please note that libsemange relies on files and directories created with
 * certain permissions. Therefore the caller should make sure the umask is
 * not too restricted (especially when called from the daemon code).
 */
int set_seuser(const char *login_name, const char *seuser_name,
               const char *mlsrange);
int del_seuser(const char *login_name);
int get_seuser(TALLOC_CTX *mem_ctx, const char *login_name,
               char **_seuser, char **_mls_range);

/* convert time from generalized form to unix time */
errno_t sss_utc_to_time_t(const char *str, const char *format, time_t *unix_time);

/* Creates a unique file using mkstemp with provided umask. The template
 * must end with XXXXXX. Returns the fd, sets _err to an errno value on error.
 *
 * Prefer using sss_unique_file() as it uses a secure umask internally.
 */
int sss_unique_file_ex(TALLOC_CTX *mem_ctx,
                       char *path_tmpl,
                       mode_t file_umask,
                       errno_t *_err);
int sss_unique_file(TALLOC_CTX *owner,
                    char *path_tmpl,
                    errno_t *_err);

/* Creates a unique filename using mkstemp with secure umask. The template
 * must end with XXXXXX
 *
 * path_tmpl must be a talloc context. Destructor would be set on the filename
 * so that it's guaranteed the file is removed.
 */
int sss_unique_filename(TALLOC_CTX *owner, char *path_tmpl);

/* from util_watchdog.c */
int setup_watchdog(struct tevent_context *ev, int interval);
void teardown_watchdog(void);

#endif /* __SSSD_UTIL_H__ */
