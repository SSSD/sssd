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
#include <sys/types.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <limits.h>
#include <sys/un.h>

#include <talloc.h>
#include <tevent.h>
#include <ldb.h>
#include <dhash.h>

#include "confdb/confdb.h"
#include "shared/io.h"
#include "shared/safealign.h"
#include "util/atomic_io.h"
#include "util/util_errors.h"
#include "util/sss_format.h"
#include "util/sss_regexp.h"
#include "util/debug.h"
#include "util/memory_erase.h"

/* name of the monitor server instance */
#define SSSD_MONITOR_NAME        "sssd"
#define SSSD_PIDFILE PID_PATH"/"SSSD_MONITOR_NAME".pid"
#define MAX_PID_LENGTH 10

#define _(STRING) gettext (STRING)

#define ENUM_INDICATOR "*"

/*
 * CLEAR_MC_FLAG is a flag file used to notify NSS responder
 * that SIGHUP signal it received was triggered by sss_cache
 * as a call for memory cache clearing. During the procedure
 * this file is deleted by NSS responder to notify back
 * sss_cache that memory cache clearing was completed.
 */
#define CLEAR_MC_FLAG "clear_mc_flag"

/* Default secure umask */
#define SSS_DFL_UMASK 0177

/* Secure mask with executable bit */
#define SSS_DFL_X_UMASK 0077

#ifndef NULL
#define NULL 0
#endif

#ifndef MIN
#define MIN(a, b)  (((a) < (b)) ? (a) : (b))
#endif

#ifndef MAX
#define MAX(a, b)  (((a) > (b)) ? (a) : (b))
#endif

#ifndef ALLPERMS
#define ALLPERMS (S_ISUID|S_ISGID|S_ISVTX|S_IRWXU|S_IRWXG|S_IRWXO)/* 07777 */
#endif

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

enum sssd_exit_status {
    CHILD_TIMEOUT_EXIT_CODE = 7,
    CA_DB_NOT_FOUND_EXIT_CODE = 50,
    SSS_WATCHDOG_EXIT_CODE = 70 /* to match EX_SOFTWARE in sysexits.h */
};

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
        switch (TRROEstate) { \
            case TEVENT_REQ_USER_ERROR:  \
                if (TRROEerr == 0) { \
                    return ERR_INTERNAL; \
                } \
                return TRROEerr; \
            case TEVENT_REQ_TIMED_OUT: \
                return ETIMEDOUT; \
            default: \
                return ERR_INTERNAL; \
        } \
    } \
} while (0)

#define OUT_OF_ID_RANGE(id, min, max) \
    (id == 0 || (min && (id < min)) || (max && (id > max)))

#include "util/dlinklist.h"

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
#define DEBUG_CHAIN_ID_FMT_RID "[RID#%"PRIu64"] %s"
#define DEBUG_CHAIN_ID_FMT_CID "[CID#%"PRIu64"] %s"

struct main_context {
    struct tevent_context *event_ctx;
    struct confdb_ctx *confdb_ctx;
    pid_t parent_pid;
};

struct sbus_request;

errno_t server_common_rotate_logs(struct confdb_ctx *confdb,
                                  const char *conf_entry);
errno_t generic_get_debug_level(TALLOC_CTX *mem_ctx,
                                struct sbus_request *sbus_req,
                                void *pvt_data,
                                uint32_t *_debug_level);
errno_t generic_set_debug_level(TALLOC_CTX *mem_ctx,
                                struct sbus_request *sbus_req,
                                void *pvt_data,
                                uint32_t new_debug_level);
int die_if_parent_died(void);
int check_pidfile(const char *file);
int pidfile(const char *file);
int server_setup(const char *name, bool is_responder,
                 int flags,
                 uid_t uid, gid_t gid,
                 const char *conf_entry,
                 struct main_context **main_ctx,
                 bool allow_sss_loop);
void server_loop(struct main_context *main_ctx);
void orderly_shutdown(int status);

/* from signal.c */
void BlockSignals(bool block, int signum);
void (*CatchSignal(int signum,void (*handler)(int )))(int);

/* from memory.c */
typedef int (void_destructor_fn_t)(void *);
/* sssd_mem_attach
 * This function will take a non-talloc pointer and "attach" it to a talloc
 * memory context. It will accept a destructor for the original pointer
 * so that when the parent memory context is freed, the non-talloc
 * pointer will also be freed properly.
 * Returns EOK in case of success.
 */
int sss_mem_attach(TALLOC_CTX *mem_ctx, void *ptr, void_destructor_fn_t *fn);

/* sss_erase_talloc_mem_securely() function always returns 0 as an int value
 * to make it possible to use it as talloc destructor.
 */
int sss_erase_talloc_mem_securely(void *p);

/* from usertools.c */
char *get_uppercase_realm(TALLOC_CTX *memctx, const char *name);

struct sss_names_ctx {
    char *re_pattern;
    char *fq_fmt;

    sss_regexp_t *re;
};

#define SSS_DEFAULT_RE "^((?P<name>.+)@(?P<domain>[^@]+)|(?P<name>[^@]+))$"

#define SSS_IPA_AD_DEFAULT_RE "^(((?P<domain>[^\\\\]+)\\\\(?P<name>.+))|" \
                              "((?P<name>.+)@(?P<domain>[^@]+))|" \
                              "((?P<name>[^@\\\\]+)))$"

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

/* Accepts fqname in the format shortname@domname only
 * and returns a pointer to domain part or NULL if not found.
 */
__attribute__((always_inline))
static inline const char *sss_get_domain_internal_fqname(const char *fqname)
{
    const char *separator = strrchr(fqname, '@');

    if (separator == NULL || *(separator + 1) == '\0' || separator == fqname) {
        /*The name does not contain name or domain component. */
        return NULL;
    }

    return (separator + 1);
}

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

/* Returns the canonical form of an IPv4 or IPv6 address */
errno_t sss_canonicalize_ip_address(TALLOC_CTX *mem_ctx,
                                    const char *address,
                                    char **canonical_address);

const char * const * get_known_services(void);

errno_t sss_user_by_name_or_uid(const char *input, uid_t *_uid, gid_t *_gid);
void sss_sssd_user_uid_and_gid(uid_t *_uid, gid_t *_gid);
void sss_set_sssd_user_eid(void);
void sss_restore_sssd_user_eid(void);

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

/* Returns true if sudoUser value is a username or a groupname */
bool is_user_or_group_name(const char *sudo_user_value);

/* Returns true if the responder has been socket-activated */
bool is_socket_activated(void);

/* Returns true if the responder has been dbus-activated */
bool is_dbus_activated(void);

/**
 * @brief Add two list of strings
 *
 * Create a new NULL-terminated list of strings by adding two lists together.
 *
 * @param[in] mem_ctx      Talloc memory context for the new list.
 * @param[in] l1           First NULL-terminated list of strings.
 * @param[in] l2           Second NULL-terminated list of strings.
 * @param[in] copy_strings If set to 'true' the list items will be copied
 *                         otherwise only the pointers to the items are
 *                         copied.
 * @param[in] skip_dups    Whether the function should skip duplicate values.
 * @param[out] new_list    New NULL-terminated list of strings. Must be freed
 *                         with talloc_free() by the caller. If copy_strings
 *                         is 'true' the new elements will be freed as well.
 */
errno_t add_strings_lists_ex(TALLOC_CTX *mem_ctx,
                             const char **l1, const char **l2,
                             bool copy_strings, bool skip_dups,
                             const char ***_new_list);

/**
 * @overload errno_t add_strings_lists_ex(TALLOC_CTX *mem_ctx,
 *                                        const char **l1, const char **l2,
 *                                        bool copy_strings, bool skip_dups,
 *                                        const char ***_new_list)
 */
static inline errno_t add_strings_lists(TALLOC_CTX *mem_ctx,
                                        const char **l1, const char **l2,
                                        bool copy_strings,
                                        const char ***_new_list)
{
    return add_strings_lists_ex(mem_ctx, l1, l2, copy_strings, false, _new_list);
}


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

/* Sanitize an input string (e.g. a DN) for use in
 * an LDAP/LDB filter
 *
 * It is basically the same as sss_filter_sanitize(_ex),
 * just extra spaces inside DN around '=' and ',' are removed
 * before sanitizing other characters . According the documentation
 * spaces in DN are allowed and some ldap servers can return them
 * in isMemberOf or member attributes.
 *
 * (dc = my example, dc = com => dc=my\20example,dc=com)
 *
 * Returns a newly-constructed string attached to mem_ctx
 * It will fail only on an out of memory condition, where it
 * will return ENOMEM.
 *
 */
errno_t sss_filter_sanitize_dn(TALLOC_CTX *mem_ctx,
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

errno_t del_string_from_list(const char *string,
                             char ***list_p, bool case_sensitive);

bool string_in_list(const char *string, char **list, bool case_sensitive);

bool string_in_list_size(const char *string, const char **list, size_t size,
                         bool case_sensitive);

int domain_to_basedn(TALLOC_CTX *memctx, const char *domain, char **basedn);

bool is_host_in_domain(const char *host, const char *domain);

bool is_valid_domain_name(const char *domain);

/* This is simple wrapper around libc rand() intended to avoid calling srand()
 * explicitly, thus *not* suitable to be used in security relevant context.
 * If CS properties are desired (security relevant functionality/FIPS/etc) then
 * use sss_crypto.h:sss_generate_csprng_buffer() instead!
 */
int sss_rand(void);

/* from nscd.c */
errno_t sss_nscd_parse_conf(const char *conf_path);

/* from sss_tc_utf8.c */
char *
sss_tc_utf8_str_tolower(TALLOC_CTX *mem_ctx, const char *s);
uint8_t *
sss_tc_utf8_tolower(TALLOC_CTX *mem_ctx, const uint8_t *s, size_t len, size_t *_nlen);
/* from sss_utf8.c */
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
/* Descend to sub-domains of current domain but do not go to next parent */
#define SSS_GND_SUBDOMAINS 0x04
#define SSS_GND_ALL_DOMAINS (SSS_GND_DESCEND | SSS_GND_INCLUDE_DISABLED)
#define SSS_GND_ALL_SUBDOMAINS (SSS_GND_SUBDOMAINS | SSS_GND_INCLUDE_DISABLED)

struct sss_domain_info *get_next_domain(struct sss_domain_info *domain,
                                        uint32_t gnd_flags);
struct sss_domain_info *find_domain_by_name(struct sss_domain_info *domain,
                                            const char *name,
                                            bool match_any);
struct sss_domain_info *find_domain_by_name_ex(struct sss_domain_info *domain,
                                               const char *name,
                                               bool match_any,
                                               uint32_t gnd_flags);
struct sss_domain_info *find_domain_by_sid(struct sss_domain_info *domain,
                                           const char *sid);
enum sss_domain_state sss_domain_get_state(struct sss_domain_info *dom);
void sss_domain_set_state(struct sss_domain_info *dom,
                          enum sss_domain_state state);
#ifdef BUILD_FILES_PROVIDER
bool sss_domain_fallback_to_nss(struct sss_domain_info *dom);
#endif
bool sss_domain_is_forest_root(struct sss_domain_info *dom);
const char *sss_domain_type_str(struct sss_domain_info *dom);

struct sss_domain_info*
sss_get_domain_by_sid_ldap_fallback(struct sss_domain_info *domain,
                                    const char* sid);

struct sss_domain_info *
find_domain_by_object_name(struct sss_domain_info *domain,
                           const char *object_name);

struct sss_domain_info *
find_domain_by_object_name_ex(struct sss_domain_info *domain,
                              const char *object_name, bool strict,
                              uint32_t gnd_flags);

bool subdomain_enumerates(struct sss_domain_info *parent,
                          const char *sd_name);

char *subdomain_create_conf_path_from_str(TALLOC_CTX *mem_ctx,
                                          const char *parent_name,
                                          const char *subdom_name);
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

bool sss_domain_is_mpg(struct sss_domain_info *domain);

bool sss_domain_is_hybrid(struct sss_domain_info *domain);

enum sss_domain_mpg_mode get_domain_mpg_mode(struct sss_domain_info *domain);
const char *str_domain_mpg_mode(enum sss_domain_mpg_mode mpg_mode);
enum sss_domain_mpg_mode str_to_domain_mpg_mode(const char *str_mpg_mode);

#define IS_SUBDOMAIN(dom) ((dom)->parent != NULL)

#define DOM_HAS_VIEWS(dom) ((dom)->has_views)

/* the directory domain - realm mappings and other krb5 config snippers are
 * written to */
#define KRB5_MAPPING_DIR PUBCONF_PATH"/krb5.include.d"

errno_t sss_get_domain_mappings_content(TALLOC_CTX *mem_ctx,
                                        struct sss_domain_info *domain,
                                        char **content);

errno_t sss_write_domain_mappings(struct sss_domain_info *domain);

char *get_hidden_tmp_path(TALLOC_CTX *mem_ctx, const char *path);

errno_t sss_write_krb5_conf_snippet(const char *path, bool canonicalize,
                                    bool udp_limit);

errno_t get_dom_names(TALLOC_CTX *mem_ctx,
                      struct sss_domain_info *start_dom,
                      char ***_dom_names,
                      int *_dom_names_count);

__attribute__((always_inline))
static inline bool is_domain_provider(struct sss_domain_info *domain,
                                      const char *provider)
{
    return domain != NULL &&
           domain->provider != NULL &&
           strcasecmp(domain->provider, provider) == 0;
}

/* Returns true if the provider used for the passed domain is the "files"
 * one. Otherwise returns false. */
__attribute__((always_inline))
static inline bool is_files_provider(struct sss_domain_info *domain)
{
#ifdef BUILD_FILES_PROVIDER
    return domain != NULL &&
           domain->provider != NULL &&
           strcasecmp(domain->provider, "files") == 0;
#else
    return false;
#endif
}

/* from util_lock.c */
errno_t sss_br_lock_file(int fd, size_t start, size_t len,
                         int num_tries, useconds_t wait);

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

void sss_replace_space_inplace(char *orig_name,
                               const char replace_char);
void sss_reverse_replace_space_inplace(char *orig_name,
                                       const char replace_char);

#define GUID_BIN_LENGTH 16
/* 16 2-digit hex values + 4 dashes + terminating 0 */
#define GUID_STR_BUF_SIZE (2 * GUID_BIN_LENGTH + 4 + 1)

errno_t guid_blob_to_string_buf(const uint8_t *blob, char *str_buf,
                                size_t buf_size);

const char *get_last_x_chars(const char *str, size_t x);
errno_t string_begins_with(const char *str, const char *prefix, bool *_result);
errno_t string_ends_with(const char *str, const char *suffix, bool *_result);

char **concatenate_string_array(TALLOC_CTX *mem_ctx,
                                char **arr1, size_t len1,
                                char **arr2, size_t len2);

errno_t mod_defaults_list(TALLOC_CTX *mem_ctx, const char **defaults_list,
                          char **mod_list, char ***_list);

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
int sss_set_seuser(const char *login_name, const char *seuser_name,
                   const char *mlsrange);
int sss_del_seuser(const char *login_name);
int sss_get_seuser(const char *linuxuser,
                   char **selinuxuser,
                   char **level);
int sss_seuser_exists(const char *linuxuser);

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
int get_watchdog_ticks(void);

/* The arm_watchdog() and disarm_watchdog() calls will disable and re-enable
 * the watchdog reset, respectively. This means that after arm_watchdog() is
 * called the watchdog will not be resetted anymore and it will kill the
 * process if disarm_watchdog() wasn't called before.
 * Those calls should only be used when there is no other way to handle
 * waiting request and recover into a stable state.
 * Those calls cannot be nested, i.e. after calling arm_watchdog() it should
 * not be called a second time in a different request because then
 * disarm_watchdog() will disable the watchdog coverage for both. */
void arm_watchdog(void);
void disarm_watchdog(void);

/* from files.c */
int sss_remove_tree(const char *root);
int sss_remove_subtree(const char *root);

int sss_copy_tree(const char *src_root,
                  const char *dst_root,
                  mode_t mode_root,
                  uid_t uid, gid_t gid);

int sss_copy_file_secure(const char *src,
                         const char *dest,
                         mode_t mode,
                         uid_t uid, gid_t gid,
                         bool force);

int sss_create_dir(const char *parent_dir_path,
                   const char *dir_name,
                   mode_t mode,
                   uid_t uid, gid_t gid);

/* from selinux.c */
int selinux_file_context(const char *dst_name);
int reset_selinux_file_context(void);

/* from cert_derb64_to_ldap_filter.c */
struct sss_certmap_ctx;
errno_t sss_cert_derb64_to_ldap_filter(TALLOC_CTX *mem_ctx, const char *derb64,
                                       const char *attr_name,
                                       struct sss_certmap_ctx *certmap_ctx,
                                       struct sss_domain_info *dom,
                                       char **ldap_filter);


/* from util_preauth.c */
errno_t create_preauth_indicator(void);

#ifdef SSSD_LIBEXEC_PATH
#define P11_CHILD_LOG_FILE "p11_child"
#define P11_CHILD_PATH SSSD_LIBEXEC_PATH"/p11_child"
#define P11_CHILD_TIMEOUT_DEFAULT 10
#define P11_WAIT_FOR_CARD_TIMEOUT_DEFAULT 60
#define PASSKEY_CHILD_TIMEOUT_DEFAULT 15
#define PASSKEY_CHILD_LOG_FILE "passkey_child"
#define PASSKEY_CHILD_PATH SSSD_LIBEXEC_PATH"/passkey_child"

#endif  /* SSSD_LIBEXEC_PATH */

#ifndef N_ELEMENTS
#define N_ELEMENTS(arr) (sizeof(arr) / sizeof(arr[0]))
#endif

/* If variable is not set, it stores a copy of default_value (if not NULL)
 * in _value but returns ENOENT so the information is propagated to the caller.
 */
errno_t sss_getenv(TALLOC_CTX *mem_ctx,
                   const char *variable_name,
                   const char *default_value,
                   char **_value);

/* from sss_time.c */
uint64_t get_start_time(void);

const char *sss_format_time(uint64_t us);
uint64_t get_spend_time_us(uint64_t st);

/* from pac_utils.h */
#define CHECK_PAC_NO_CHECK_STR "no_check"
#define CHECK_PAC_PRESENT_STR "pac_present"
#define CHECK_PAC_PRESENT (1 << 0)
#define CHECK_PAC_CHECK_UPN_STR "check_upn"
#define CHECK_PAC_CHECK_UPN (1 << 1)
#define CHECK_PAC_UPN_DNS_INFO_PRESENT_STR "upn_dns_info_present"
#define CHECK_PAC_UPN_DNS_INFO_PRESENT (1 << 2)
#define CHECK_PAC_CHECK_UPN_DNS_INFO_EX_STR "check_upn_dns_info_ex"
#define CHECK_PAC_CHECK_UPN_DNS_INFO_EX (1 << 3)
#define CHECK_PAC_UPN_DNS_INFO_EX_PRESENT_STR "upn_dns_info_ex_present"
#define CHECK_PAC_UPN_DNS_INFO_EX_PRESENT (1 << 4)
#define CHECK_PAC_CHECK_UPN_ALLOW_MISSING_STR "check_upn_allow_missing"
#define CHECK_PAC_CHECK_UPN_ALLOW_MISSING (1 << 5)

errno_t get_pac_check_config(struct confdb_ctx *cdb, uint32_t *pac_check_opts);

static inline struct timeval sss_tevent_timeval_current_ofs_time_t(time_t secs)
{
    uint32_t secs32 = (secs > UINT_MAX ? UINT_MAX : secs);
    return tevent_timeval_current_ofs(secs32, 0);
}

/* parsed uri */
struct sss_parsed_dns_uri {
    const char *scheme;
    const char *address;
    const char *port;
    const char *host;
    const char *path;

    char *data;
};

errno_t sss_parse_dns_uri(TALLOC_CTX *ctx,
                          const char *uri,
                          struct sss_parsed_dns_uri **_parsed_uri);

#endif /* __SSSD_UTIL_H__ */
