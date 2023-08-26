/*
    SSSD

    LDAP Helper routines

    Copyright (C) Simo Sorce <ssorce@redhat.com>

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

#ifndef _SDAP_H_
#define _SDAP_H_

#include <ldb.h>
#include "providers/backend.h"
#include <ldap.h>
#include "util/sss_ldap.h"
#include "lib/certmap/sss_certmap.h"

struct sdap_msg {
    struct sdap_msg *next;
    LDAPMessage *msg;
};

struct sdap_op;

typedef void (sdap_op_callback_t)(struct sdap_op *op,
                                  struct sdap_msg *, int, void *);

struct sdap_handle;

struct fd_event_item {
    struct fd_event_item *prev;
    struct fd_event_item *next;

    int fd;
    struct tevent_fd *fde;
};

struct ldap_cb_data {
    struct sdap_handle *sh;
    struct tevent_context *ev;
    struct fd_event_item *fd_list;
};

struct sup_list {
    int num_vals;
    char **vals;
};

struct sdap_handle {
    LDAP *ldap;
    bool connected;
    /* Authentication ticket expiration time (if any) */
    time_t expire_time;
    /* Time when the connection became idle (if any) */
    time_t idle_time;
    /* Configured idle timeout */
    int idle_timeout;
    ber_int_t page_size;
    bool disable_deref;

    struct sdap_fd_events *sdap_fd_events;

    struct sup_list supported_saslmechs;
    struct sup_list supported_controls;
    struct sup_list supported_extensions;

    struct sdap_op *ops;

    /* during release we need to lock access to the handler
     * from the destructor to avoid recursion */
    bool destructor_lock;
    /* mark when it is safe to finally release the handler memory */
    bool release_memory;
};

struct sdap_service {
    char *name;
    char *uri;
    char *kinit_service_name;
    struct sockaddr *sockaddr;
    socklen_t sockaddr_len;
};

struct sdap_ppolicy_data {
    int grace;
    int expire;
};

#define SYSDB_SHADOWPW_LASTCHANGE "shadowLastChange"
#define SYSDB_SHADOWPW_MIN "shadowMin"
#define SYSDB_SHADOWPW_MAX "shadowMax"
#define SYSDB_SHADOWPW_WARNING "shadowWarning"
#define SYSDB_SHADOWPW_INACTIVE "shadowInactive"
#define SYSDB_SHADOWPW_EXPIRE "shadowExpire"
#define SYSDB_SHADOWPW_FLAG "shadowFlag"

#define SYSDB_NS_ACCOUNT_LOCK "nsAccountLock"

#define SYSDB_KRBPW_LASTCHANGE "krbLastPwdChange"
#define SYSDB_KRBPW_EXPIRATION "krbPasswordExpiration"

#define SYSDB_PWD_ATTRIBUTE "pwdAttribute"

#define SYSDB_NDS_LOGIN_DISABLED "ndsLoginDisabled"
#define SYSDB_NDS_LOGIN_EXPIRATION_TIME "ndsLoginExpirationTime"
#define SYSDB_NDS_LOGIN_ALLOWED_TIME_MAP "ndsLoginAllowedTimeMap"

#define SDAP_ROOTDSE_ATTR_NAMING_CONTEXTS "namingContexts"
#define SDAP_ROOTDSE_ATTR_DEFAULT_NAMING_CONTEXT "defaultNamingContext"
#define SDAP_ROOTDSE_ATTR_AD_VERSION "domainControllerFunctionality"
#define SDAP_ROOTDSE_ATTR_AD_SCHEMA_NC "schemaNamingContext"

#define SDAP_IPA_USN "entryUSN"
#define SDAP_IPA_LAST_USN "lastUSN"
#define SDAP_AD_USN "uSNChanged"
#define SDAP_AD_LAST_USN "highestCommittedUSN"

#define SDAP_AD_GROUP_TYPE_BUILTIN      0x00000001
#define SDAP_AD_GROUP_TYPE_GLOBAL       0x00000002
#define SDAP_AD_GROUP_TYPE_DOMAIN_LOCAL 0x00000004
#define SDAP_AD_GROUP_TYPE_UNIVERSAL    0x00000008
#define SDAP_AD_GROUP_TYPE_APP_BASIC    0x00000010
#define SDAP_AD_GROUP_TYPE_APP_QUERY    0x00000020
#define SDAP_AD_GROUP_TYPE_SECURITY     0x80000000

enum sdap_basic_opt {
    SDAP_URI = 0,
    SDAP_BACKUP_URI,
    SDAP_SEARCH_BASE,
    SDAP_DEFAULT_BIND_DN,
    SDAP_DEFAULT_AUTHTOK_TYPE,
    SDAP_DEFAULT_AUTHTOK,
    SDAP_SEARCH_TIMEOUT,
    SDAP_NETWORK_TIMEOUT,
    SDAP_OPT_TIMEOUT,
    SDAP_TLS_REQCERT,
    SDAP_USER_SEARCH_BASE,
    SDAP_USER_SEARCH_SCOPE,
    SDAP_USER_SEARCH_FILTER,
    SDAP_USER_EXTRA_ATTRS,
    SDAP_GROUP_SEARCH_BASE,
    SDAP_GROUP_SEARCH_SCOPE,
    SDAP_GROUP_SEARCH_FILTER,
    SDAP_HOST_SEARCH_BASE,
    SDAP_SERVICE_SEARCH_BASE,
    SDAP_SUDO_SEARCH_BASE,
    SDAP_SUDO_FULL_REFRESH_INTERVAL,
    SDAP_SUDO_SMART_REFRESH_INTERVAL,
    SDAP_SUDO_RANDOM_OFFSET,
    SDAP_SUDO_USE_HOST_FILTER,
    SDAP_SUDO_HOSTNAMES,
    SDAP_SUDO_IP,
    SDAP_SUDO_INCLUDE_NETGROUPS,
    SDAP_SUDO_INCLUDE_REGEXP,
    SDAP_AUTOFS_SEARCH_BASE,
    SDAP_AUTOFS_MAP_MASTER_NAME,
    SDAP_IPHOST_SEARCH_BASE,
    SDAP_IPNETWORK_SEARCH_BASE,
    SDAP_SCHEMA,
    SDAP_PWMODIFY_MODE,
    SDAP_OFFLINE_TIMEOUT,
    SDAP_FORCE_UPPER_CASE_REALM,
    SDAP_ENUM_REFRESH_TIMEOUT,
    SDAP_ENUM_REFRESH_OFFSET,
    SDAP_PURGE_CACHE_TIMEOUT,
    SDAP_PURGE_CACHE_OFFSET,
    SDAP_TLS_CACERT,
    SDAP_TLS_CACERTDIR,
    SDAP_TLS_CERT,
    SDAP_TLS_KEY,
    SDAP_TLS_CIPHER_SUITE,
    SDAP_ID_TLS,
    SDAP_ID_MAPPING,
    SDAP_SASL_MECH,
    SDAP_SASL_AUTHID,
    SDAP_SASL_REALM,
    SDAP_SASL_MINSSF,
    SDAP_SASL_MAXSSF,
    SDAP_KRB5_KEYTAB,
    SDAP_KRB5_KINIT,
    SDAP_KRB5_KDC,
    SDAP_KRB5_BACKUP_KDC,
    SDAP_KRB5_REALM,
    SDAP_KRB5_CANONICALIZE,
    SDAP_KRB5_USE_KDCINFO,
    SDAP_KRB5_KDCINFO_LOOKAHEAD,
    SDAP_PWD_POLICY,
    SDAP_REFERRALS,
    SDAP_ACCOUNT_CACHE_EXPIRATION,
    SDAP_DNS_SERVICE_NAME,
    SDAP_KRB5_TICKET_LIFETIME,
    SDAP_ACCESS_FILTER,
    SDAP_NETGROUP_SEARCH_BASE,
    SDAP_NESTING_LEVEL,
    SDAP_DEREF,
    SDAP_ACCOUNT_EXPIRE_POLICY,
    SDAP_ACCESS_ORDER,
    SDAP_CHPASS_URI,
    SDAP_CHPASS_BACKUP_URI,
    SDAP_CHPASS_DNS_SERVICE_NAME,
    SDAP_CHPASS_UPDATE_LAST_CHANGE,
    SDAP_ENUM_SEARCH_TIMEOUT,
    SDAP_DISABLE_AUTH_TLS,
    SDAP_PAGE_SIZE,
    SDAP_DEREF_THRESHOLD,
    SDAP_IGNORE_UNREADABLE_REFERENCES,
    SDAP_SASL_CANONICALIZE,
    SDAP_EXPIRE_TIMEOUT,
    SDAP_EXPIRE_OFFSET,
    SDAP_IDLE_TIMEOUT,
    SDAP_DISABLE_PAGING,
    SDAP_IDMAP_LOWER,
    SDAP_IDMAP_UPPER,
    SDAP_IDMAP_RANGESIZE,
    SDAP_IDMAP_AUTORID_COMPAT,
    SDAP_IDMAP_DEFAULT_DOMAIN,
    SDAP_IDMAP_DEFAULT_DOMAIN_SID,
    SDAP_IDMAP_EXTRA_SLICE_INIT,
    SDAP_AD_USE_TOKENGROUPS,
    SDAP_RFC2307_FALLBACK_TO_LOCAL_USERS,
    SDAP_DISABLE_RANGE_RETRIEVAL,
    SDAP_MIN_ID,
    SDAP_MAX_ID,
    SDAP_PWDLOCKOUT_DN,
    SDAP_WILDCARD_LIMIT,
    SDAP_LIBRARY_DEBUG_LEVEL,
    SDAP_USE_PPOLICY,

    SDAP_OPTS_BASIC /* opts counter */
};

enum sdap_gen_attrs {
    SDAP_AT_ENTRY_USN = 0,
    SDAP_AT_LAST_USN,

    SDAP_AT_GENERAL /* attrs counter */
};

/* the objectclass must be the first attribute.
 * Functions depend on this */
enum sdap_user_attrs {
    SDAP_OC_USER = 0,
    SDAP_AT_USER_NAME,
    SDAP_AT_USER_PWD,
    SDAP_AT_USER_UID,
    SDAP_AT_USER_GID,
    SDAP_AT_USER_GECOS,
    SDAP_AT_USER_HOME,
    SDAP_AT_USER_SHELL,
    SDAP_AT_USER_PRINC,
    SDAP_AT_USER_FULLNAME,
    SDAP_AT_USER_MEMBEROF,
    SDAP_AT_USER_UUID,
    SDAP_AT_USER_OBJECTSID,
    SDAP_AT_USER_PRIMARY_GROUP,
    SDAP_AT_USER_MODSTAMP,
    SDAP_AT_USER_USN,
    SDAP_AT_SP_LSTCHG,
    SDAP_AT_SP_MIN,
    SDAP_AT_SP_MAX,
    SDAP_AT_SP_WARN,
    SDAP_AT_SP_INACT,
    SDAP_AT_SP_EXPIRE,
    SDAP_AT_SP_FLAG,
    SDAP_AT_KP_LASTCHANGE,
    SDAP_AT_KP_EXPIRATION,
    SDAP_AT_PWD_ATTRIBUTE,
    SDAP_AT_AUTH_SVC,
    SDAP_AT_AD_ACCOUNT_EXPIRES,
    SDAP_AT_AD_USER_ACCOUNT_CONTROL,
    SDAP_AT_NS_ACCOUNT_LOCK,
    SDAP_AT_AUTHORIZED_HOST,
    SDAP_AT_AUTHORIZED_RHOST,
    SDAP_AT_NDS_LOGIN_DISABLED,
    SDAP_AT_NDS_LOGIN_EXPIRATION_TIME,
    SDAP_AT_NDS_LOGIN_ALLOWED_TIME_MAP,
    SDAP_AT_USER_SSH_PUBLIC_KEY,
    SDAP_AT_USER_AUTH_TYPE,
    SDAP_AT_USER_CERT,
    SDAP_AT_USER_EMAIL,
    SDAP_AT_USER_PASSKEY,

    SDAP_OPTS_USER /* attrs counter */
};

#define SDAP_FIRST_EXTRA_USER_AT SDAP_AT_SP_LSTCHG

/* the objectclass must be the first attribute.
 * Functions depend on this */
enum sdap_group_attrs {
    SDAP_OC_GROUP = 0,
    SDAP_OC_GROUP_ALT,
    SDAP_AT_GROUP_NAME,
    SDAP_AT_GROUP_PWD,
    SDAP_AT_GROUP_GID,
    SDAP_AT_GROUP_MEMBER,
    SDAP_AT_GROUP_UUID,
    SDAP_AT_GROUP_OBJECTSID,
    SDAP_AT_GROUP_MODSTAMP,
    SDAP_AT_GROUP_USN,
    SDAP_AT_GROUP_TYPE,
    SDAP_AT_GROUP_EXT_MEMBER,

    SDAP_OPTS_GROUP /* attrs counter */
};

enum sdap_netgroup_attrs {
    SDAP_OC_NETGROUP = 0,
    SDAP_AT_NETGROUP_NAME,
    SDAP_AT_NETGROUP_MEMBER,
    SDAP_AT_NETGROUP_TRIPLE,
    SDAP_AT_NETGROUP_MODSTAMP,

    SDAP_OPTS_NETGROUP /* attrs counter */
};

enum sdap_sudorule_attrs {
    SDAP_OC_SUDORULE = 0,
    SDAP_AT_SUDO_OC,
    SDAP_AT_SUDO_NAME,
    SDAP_AT_SUDO_COMMAND,
    SDAP_AT_SUDO_HOST,
    SDAP_AT_SUDO_USER,
    SDAP_AT_SUDO_OPTION,
    SDAP_AT_SUDO_RUNAS,
    SDAP_AT_SUDO_RUNASUSER,
    SDAP_AT_SUDO_RUNASGROUP,
    SDAP_AT_SUDO_NOTBEFORE,
    SDAP_AT_SUDO_NOTAFTER,
    SDAP_AT_SUDO_ORDER,
    SDAP_AT_SUDO_USN,

    SDAP_OPTS_SUDO  /* attrs counter */
};

enum sdap_host_attrs {
    SDAP_OC_HOST = 0,
    SDAP_AT_HOST_NAME,
    SDAP_AT_HOST_FQDN,
    SDAP_AT_HOST_SERVERHOSTNAME,
    SDAP_AT_HOST_MEMBER_OF,
    SDAP_AT_HOST_SSH_PUBLIC_KEY,
    SDAP_AT_HOST_UUID,

    SDAP_OPTS_HOST /* attrs counter */
};

enum sdap_service_attrs {
    SDAP_OC_SERVICE = 0,
    SDAP_AT_SERVICE_NAME,
    SDAP_AT_SERVICE_PORT,
    SDAP_AT_SERVICE_PROTOCOL,
    SDAP_AT_SERVICE_USN,
    SDAP_OPTS_SERVICES /* attrs counter */
};

enum sdap_iphost_entry_attrs {
    SDAP_OC_IPHOST = 0,
    SDAP_AT_IPHOST_NAME,
    SDAP_AT_IPHOST_NUMBER,
    SDAP_AT_IPHOST_USN,

    SDAP_OPTS_IPHOST /* attrs counter */
};

enum sdap_ipnetwork_entry_attrs {
    SDAP_OC_IPNETWORK = 0,
    SDAP_AT_IPNETWORK_NAME,
    SDAP_AT_IPNETWORK_NUMBER,
    SDAP_AT_IPNETWORK_USN,

    SDAP_OPTS_IPNETWORK /* attrs counter */
};

#ifdef BUILD_SUBID
enum sdap_subid_range_attrs {
    SDAP_OC_SUBID_RANGE = 0,
    SDAP_AT_SUBID_RANGE_UID_COUNT,
    SDAP_AT_SUBID_RANGE_GID_COUNT,
    SDAP_AT_SUBID_RANGE_UID_NUMBER,
    SDAP_AT_SUBID_RANGE_GID_NUMBER,
    SDAP_AT_SUBID_RANGE_OWNER,

    SDAP_OPTS_SUBID_RANGE /* attrs counter */
};
#endif

enum sdap_autofs_map_attrs {
    SDAP_OC_AUTOFS_MAP,
    SDAP_AT_AUTOFS_MAP_NAME,

    SDAP_OPTS_AUTOFS_MAP    /* attrs counter */
};

enum sdap_autofs_entry_attrs {
    SDAP_OC_AUTOFS_ENTRY,
    SDAP_AT_AUTOFS_ENTRY_KEY,
    SDAP_AT_AUTOFS_ENTRY_VALUE,

    SDAP_OPTS_AUTOFS_ENTRY  /* attrs counter */
};

struct sdap_attr_map {
    const char *opt_name;
    const char *def_name;
    const char *sys_name;
    char *name;
};
#define SDAP_ATTR_MAP_TERMINATOR { NULL, NULL, NULL, NULL }

struct sdap_search_base {
    const char *basedn;
    struct ldb_context *ldb;
    struct ldb_dn *ldb_basedn;
    int scope;
    const char *filter;
};

errno_t
sdap_create_search_base(TALLOC_CTX *mem_ctx,
                        struct ldb_context *ldb,
                        const char *unparsed_base,
                        int scope,
                        const char *filter,
                        struct sdap_search_base **_base);

/* Values from
 * http://msdn.microsoft.com/en-us/library/cc223272%28v=prot.13%29.aspx
 */
enum dc_functional_level {
    DS_BEHAVIOR_WIN2000 = 0,
    DS_BEHAVIOR_WIN2003 = 2,
    DS_BEHAVIOR_WIN2008 = 3,
    DS_BEHAVIOR_WIN2008R2 = 4,
    DS_BEHAVIOR_WIN2012 = 5,
    DS_BEHAVIOR_WIN2012R2 = 6,
    DS_BEHAVIOR_WIN2016 = 7,
};

struct sdap_domain {
    struct sss_domain_info *dom;

    char *basedn;

    struct sdap_search_base **search_bases;
    struct sdap_search_base **user_search_bases;
    struct sdap_search_base **group_search_bases;
    struct sdap_search_base **netgroup_search_bases;
    struct sdap_search_base **host_search_bases;
    struct sdap_search_base **sudo_search_bases;
    struct sdap_search_base **service_search_bases;
    struct sdap_search_base **iphost_search_bases;
    struct sdap_search_base **ipnetwork_search_bases;
    struct sdap_search_base **autofs_search_bases;
    struct sdap_search_base **ignore_user_search_bases;
#ifdef BUILD_SUBID
    struct sdap_search_base **subid_ranges_search_bases;
#endif

    struct sdap_domain *next, *prev;
    /* Need to modify the list from a talloc destructor */
    struct sdap_domain **head;

    void *pvt;
};

typedef struct tevent_req *
(*ext_member_send_fn_t)(TALLOC_CTX *mem_ctx,
                        struct tevent_context *ev,
                        const char *ext_member,
                        void *pvt);
typedef errno_t
(*ext_member_recv_fn_t)(TALLOC_CTX *mem_ctx,
                        struct tevent_req *req,
                        enum sysdb_member_type *member_type,
                        struct sss_domain_info **_dom,
                        struct sysdb_attrs **_member);

struct sdap_ext_member_ctx {
    /* Typically ID context of the external ID provider */
    void *pvt;

    ext_member_send_fn_t ext_member_resolve_send;
    ext_member_recv_fn_t ext_member_resolve_recv;
};

struct sdap_certmap_ctx;

struct sdap_options {
    struct dp_option *basic;
    struct data_provider *dp;
    struct sdap_attr_map *gen_map;
    struct sdap_attr_map *user_map;
    size_t user_map_cnt;
    struct sdap_attr_map *group_map;
    struct sdap_attr_map *netgroup_map;
    struct sdap_attr_map *host_map;
    struct sdap_attr_map *service_map;
    struct sdap_attr_map *iphost_map;
    struct sdap_attr_map *ipnetwork_map;
#ifdef BUILD_SUBID
    struct sdap_attr_map *subid_map;
#endif

    /* ID-mapping support */
    struct sdap_idmap_ctx *idmap_ctx;

    /* Resolving external members */
    struct sdap_ext_member_ctx *ext_ctx;

    /* FIXME - should this go to a special struct to avoid mixing with name-service-switch maps? */
    struct sdap_attr_map *sudorule_map;
    struct sdap_attr_map *autofs_mobject_map;
    struct sdap_attr_map *autofs_entry_map;

    /* supported schema types */
    enum schema_type {
        SDAP_SCHEMA_RFC2307 = 1,    /* memberUid = uid */
        SDAP_SCHEMA_RFC2307BIS = 2, /* member = dn */
        SDAP_SCHEMA_IPA_V1 = 3,     /* member/memberof */
        SDAP_SCHEMA_AD = 4          /* AD's member/memberof */
    } schema_type;

    /* password modify mode */
    enum pwmodify_mode {
        SDAP_PWMODIFY_EXOP = 1,     /* pwmodify extended operation */
        SDAP_PWMODIFY_LDAP = 2      /* ldap_modify of userPassword */
    } pwmodify_mode;

    /* The search bases for the domain or its subdomain */
    struct sdap_domain *sdom;

    /* The options below are normally only used with AD */
    bool support_matching_rule;
    enum dc_functional_level dc_functional_level;
    const char *schema_basedn;
    bool allow_remote_domain_local_groups;

    /* Certificate mapping support */
    struct sdap_certmap_ctx *sdap_certmap_ctx;
};

struct sdap_server_opts {
    char *server_id;
    bool supports_usn;
    unsigned long last_usn;
    char *max_user_value;
    char *max_group_value;
    char *max_service_value;
    char *max_sudo_value;
    char *max_iphost_value;
    char *max_ipnetwork_value;
};

struct sdap_id_ctx;

struct sdap_attr_map_info {
    struct sdap_attr_map *map;
    int num_attrs;
};

struct sdap_deref_attrs {
    struct sdap_attr_map *map;
    struct sysdb_attrs *attrs;
};

errno_t sdap_copy_map_entry(const struct sdap_attr_map *src_map,
                            struct sdap_attr_map *dst_map,
                            int entry_index);

int sdap_copy_map(TALLOC_CTX *memctx,
                 struct sdap_attr_map *src_map,
                 int num_entries,
                 struct sdap_attr_map **_map);

/**
 * @brief Add attributes to a map
 *
 * sdap_extend_map() will call talloc_realloc() on the second argument so the
 * original storage location might change. The return value _map will always
 * contain the current memory location which can be used with talloc_free()
 * even if there is an error.
 *
 * @param[in] memctx      Talloc memory context
 * @param[in] src_map     Original map, should not be accessed anymore
 * @param[in] num_entries Number of entries in the original map
 * @param[in] extra_attrs NULL-terminated array of extra attribute pairs
 *                        sysdb_attr:ldap_attr
 * @param[out] _map       New map
 * @param[out] _new_size  Number of entries in the new map
 *
 * @return
 *  - EOK                 success
 *  - ENOMEM              memory allocation failed
 *  - ERR_DUP_EXTRA_ATTR  sysdb attribute is already used
 */
int sdap_extend_map(TALLOC_CTX *memctx,
                    struct sdap_attr_map *src_map,
                    size_t num_entries,
                    char **extra_attrs,
                    struct sdap_attr_map **_map,
                    size_t *_new_size);

int sdap_extend_map_with_list(TALLOC_CTX *mem_ctx,
                              const struct sdap_options *opts,
                              int extra_attr_index,
                              struct sdap_attr_map *src_map,
                              size_t num_entries,
                              struct sdap_attr_map **_map,
                              size_t *_new_size);

void sdap_inherit_options(char **inherit_opt_list,
                          struct sdap_options *parent_sdap_opts,
                          struct sdap_options *child_sdap_opts);

int sdap_get_map(TALLOC_CTX *memctx,
                 struct confdb_ctx *cdb,
                 const char *conf_path,
                 struct sdap_attr_map *def_map,
                 int num_entries,
                 struct sdap_attr_map **_map);

int sdap_parse_entry(TALLOC_CTX *memctx,
                     struct sdap_handle *sh, struct sdap_msg *sm,
                     struct sdap_attr_map *map, int attrs_num,
                     struct sysdb_attrs **_attrs,
                     bool disable_range_retrieval);

errno_t sdap_parse_deref(TALLOC_CTX *mem_ctx,
                         struct sdap_attr_map_info *minfo,
                         size_t num_maps,
                         LDAPDerefRes *dref,
                         struct sdap_deref_attrs ***_deref_res);

void setup_ldap_debug(struct dp_option *basic_opts);

errno_t setup_tls_config(struct dp_option *basic_opts);

int sdap_set_rootdse_supported_lists(struct sysdb_attrs *rootdse,
                                     struct sdap_handle *sh);
bool sdap_check_sup_list(struct sup_list *l, const char *val);

#define sdap_is_sasl_mech_supported(sh, sasl_mech) \
    sdap_check_sup_list(&((sh)->supported_saslmechs), sasl_mech)

#define sdap_is_control_supported(sh, ctrl_oid) \
    sdap_check_sup_list(&((sh)->supported_controls), ctrl_oid)

#define sdap_is_extension_supported(sh, ext_oid) \
    sdap_check_sup_list(&((sh)->supported_extensions), ext_oid)

bool sdap_sasl_mech_needs_kinit(const char *mech);

int build_attrs_from_map(TALLOC_CTX *memctx,
                         struct sdap_attr_map *map,
                         size_t size,
                         const char **filter,
                         const char ***_attrs,
                         size_t *attr_count);

int sdap_control_create(struct sdap_handle *sh, const char *oid, int iscritical,
                        struct berval *value, int dupval, LDAPControl **ctrlp);

int sdap_replace_id(struct sysdb_attrs *entry, const char *attr, id_t val);

errno_t sdap_get_group_primary_name(TALLOC_CTX *memctx,
                                    struct sdap_options *opts,
                                    struct sysdb_attrs *attrs,
                                    struct sss_domain_info *dom,
                                    const char **_group_name);

errno_t sdap_get_user_primary_name(TALLOC_CTX *memctx,
                                   struct sdap_options *opts,
                                   struct sysdb_attrs *attrs,
                                   struct sss_domain_info *dom,
                                   const char **_user_name);

errno_t sdap_get_netgroup_primary_name(struct sdap_options *opts,
                                       struct sysdb_attrs *attrs,
                                       const char **_netgroup_name);

errno_t sdap_get_primary_name(const char *attr_name,
                              struct sysdb_attrs *attrs,
                              const char **_primary_name);

errno_t sdap_get_primary_name_list(struct sss_domain_info *domain,
                                   TALLOC_CTX *mem_ctx,
                                   struct sysdb_attrs **attr_list,
                                   size_t attr_count,
                                   const char *ldap_attr,
                                   char ***name_list);

errno_t sdap_get_primary_fqdn_list(struct sss_domain_info *domain,
                                   TALLOC_CTX *mem_ctx,
                                   struct sysdb_attrs **attr_list,
                                   size_t attr_count,
                                   const char *ldap_attr,
                                   char ***name_list);

errno_t sdap_set_config_options_with_rootdse(struct sysdb_attrs *rootdse,
                                             struct sdap_options *opts,
                                             struct sdap_domain *sdom);
int sdap_get_server_opts_from_rootdse(TALLOC_CTX *memctx,
                                      const char *server,
                                      struct sysdb_attrs *rootdse,
                                      struct sdap_options *opts,
                                      struct sdap_server_opts **srv_opts);
void sdap_steal_server_opts(struct sdap_id_ctx *id_ctx,
                            struct sdap_server_opts **srv_opts);

char *sdap_make_oc_list(TALLOC_CTX *mem_ctx, struct sdap_attr_map *map);

size_t sdap_steal_objects_in_dom(struct sdap_options *opts,
                                 struct sysdb_attrs **dom_objects,
                                 size_t offset,
                                 struct sss_domain_info *dom,
                                 struct sysdb_attrs **all_objects,
                                 size_t count,
                                 bool filter);

struct sss_domain_info *sdap_get_object_domain(struct sdap_options *opts,
                                               struct sysdb_attrs *obj,
                                               struct sss_domain_info *dom);

bool sdap_object_in_domain(struct sdap_options *opts,
                           struct sysdb_attrs *obj,
                           struct sss_domain_info *dom);

void sdap_domain_copy_search_bases(struct sdap_domain *to,
                                   struct sdap_domain *from);

#endif /* _SDAP_H_ */
