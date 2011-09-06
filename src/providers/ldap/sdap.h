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

#include "providers/dp_backend.h"
#include <ldap.h>
#include "util/sss_ldap.h"

struct sdap_msg {
    struct sdap_msg *next;
    LDAPMessage *msg;
};

struct sdap_op;

typedef void (sdap_op_callback_t)(struct sdap_op *op,
                                  struct sdap_msg *, int, void *);

struct sdap_handle;

struct sdap_op {
    struct sdap_op *prev, *next;
    struct sdap_handle *sh;

    int msgid;
    bool done;

    sdap_op_callback_t *callback;
    void *data;

    struct tevent_context *ev;
    struct sdap_msg *list;
    struct sdap_msg *last;
};

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
    ber_int_t page_size;

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
    struct sockaddr_storage *sockaddr;
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

#define SYSDB_AD_ACCOUNT_EXPIRES "adAccountExpires"
#define SYSDB_AD_USER_ACCOUNT_CONTROL "adUserAccountControl"

#define SDAP_ROOTDSE_ATTR_NAMING_CONTEXTS "namingContexts"
#define SDAP_ROOTDSE_ATTR_DEFAULT_NAMING_CONTEXT "defaultNamingContext"

#define SDAP_IPA_USN "entryUSN"
#define SDAP_IPA_LAST_USN "lastUSN"
#define SDAP_AD_USN "uSNChanged"
#define SDAP_AD_LAST_USN "highestCommittedUSN"

enum sdap_result {
    SDAP_SUCCESS,
    SDAP_NOT_FOUND,
    SDAP_UNAVAIL,
    SDAP_RETRY,
    SDAP_ERROR,
    SDAP_AUTH_SUCCESS,
    SDAP_AUTH_FAILED,
    SDAP_AUTH_PW_EXPIRED,
    SDAP_AUTH_PW_CONSTRAINT_VIOLATION,
    SDAP_ACCT_EXPIRED
};

enum sdap_basic_opt {
    SDAP_URI = 0,
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
    SDAP_GROUP_SEARCH_BASE,
    SDAP_GROUP_SEARCH_SCOPE,
    SDAP_GROUP_SEARCH_FILTER,
    SDAP_SCHEMA,
    SDAP_OFFLINE_TIMEOUT,
    SDAP_FORCE_UPPER_CASE_REALM,
    SDAP_ENUM_REFRESH_TIMEOUT,
    SDAP_CACHE_PURGE_TIMEOUT,
    SDAP_ENTRY_CACHE_TIMEOUT,
    SDAP_TLS_CACERT,
    SDAP_TLS_CACERTDIR,
    SDAP_TLS_CERT,
    SDAP_TLS_KEY,
    SDAP_TLS_CIPHER_SUITE,
    SDAP_ID_TLS,
    SDAP_SASL_MECH,
    SDAP_SASL_AUTHID,
    SDAP_KRB5_KEYTAB,
    SDAP_KRB5_KINIT,
    SDAP_KRB5_KDC,
    SDAP_KRB5_REALM,
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
    SDAP_CHPASS_DNS_SERVICE_NAME,
    SDAP_ENUM_SEARCH_TIMEOUT,
    SDAP_DISABLE_AUTH_TLS,
    SDAP_PAGE_SIZE,
    SDAP_SASL_CANONICALIZE,

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

    SDAP_OPTS_USER /* attrs counter */
};

#define SDAP_FIRST_EXTRA_USER_AT SDAP_AT_SP_LSTCHG

/* the objectclass must be the first attribute.
 * Functions depend on this */
enum sdap_group_attrs {
    SDAP_OC_GROUP = 0,
    SDAP_AT_GROUP_NAME,
    SDAP_AT_GROUP_PWD,
    SDAP_AT_GROUP_GID,
    SDAP_AT_GROUP_MEMBER,
    SDAP_AT_GROUP_UUID,
    SDAP_AT_GROUP_MODSTAMP,
    SDAP_AT_GROUP_USN,

    SDAP_OPTS_GROUP /* attrs counter */
};

enum sdap_netgroup_attrs {
    SDAP_OC_NETGROUP = 0,
    SDAP_AT_NETGROUP_NAME,
    SDAP_AT_NETGROUP_MEMBER,
    SDAP_AT_NETGROUP_TRIPLE,
    SDAP_AT_NETGROUP_UUID,
    SDAP_AT_NETGROUP_MODSTAMP,

    SDAP_OPTS_NETGROUP /* attrs counter */
};

struct sdap_attr_map {
    const char *opt_name;
    const char *def_name;
    const char *sys_name;
    char *name;
};

struct sdap_options {
    struct dp_option *basic;
    struct sdap_attr_map *gen_map;
    struct sdap_attr_map *user_map;
    struct sdap_attr_map *group_map;
    struct sdap_attr_map *netgroup_map;

    /* supported schema types */
    enum schema_type {
        SDAP_SCHEMA_RFC2307 = 1,    /* memberUid = uid */
        SDAP_SCHEMA_RFC2307BIS = 2, /* member = dn */
        SDAP_SCHEMA_IPA_V1 = 3,     /* member/memberof */
        SDAP_SCHEMA_AD = 4          /* AD's member/memberof */
    } schema_type;

    struct ldb_dn *users_base;
    struct ldb_dn *groups_base;
};

struct sdap_server_opts {
    char *server_id;
    bool supports_usn;
    char *max_user_value;
    char *max_group_value;
};

struct sdap_id_ctx;

int sdap_get_map(TALLOC_CTX *memctx,
                 struct confdb_ctx *cdb,
                 const char *conf_path,
                 struct sdap_attr_map *def_map,
                 int num_entries,
                 struct sdap_attr_map **_map);

int sdap_parse_entry(TALLOC_CTX *memctx,
                     struct sdap_handle *sh, struct sdap_msg *sm,
                     struct sdap_attr_map *map, int attrs_num,
                     struct sysdb_attrs **_attrs, char **_dn);

int sdap_parse_user(TALLOC_CTX *memctx, struct sdap_options *opts,
                    struct sdap_handle *sh, struct sdap_msg *sm,
                    struct sysdb_attrs **_attrs, char **_dn);

int sdap_parse_group(TALLOC_CTX *memctx, struct sdap_options *opts,
                     struct sdap_handle *sh, struct sdap_msg *sm,
                     struct sysdb_attrs **_attrs, char **_dn);

int sdap_get_msg_dn(TALLOC_CTX *memctx, struct sdap_handle *sh,
                    struct sdap_msg *sm, char **_dn);

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

int build_attrs_from_map(TALLOC_CTX *memctx,
                         struct sdap_attr_map *map,
                         size_t size, const char ***_attrs);
int append_attrs_to_array(const char **attrs, size_t size, const char *attr);

int sdap_control_create(struct sdap_handle *sh, const char *oid, int iscritical,
                        struct berval *value, int dupval, LDAPControl **ctrlp);

errno_t sdap_set_config_options_with_rootdse(struct sysdb_attrs *rootdse,
                                             struct sdap_handle *sh,
                                             struct sdap_options *opts);
int sdap_get_server_opts_from_rootdse(TALLOC_CTX *memctx,
                                      const char *server,
                                      struct sysdb_attrs *rootdse,
                                      struct sdap_options *opts,
                                      struct sdap_server_opts **srv_opts);
void sdap_steal_server_opts(struct sdap_id_ctx *id_ctx,
                            struct sdap_server_opts **srv_opts);
#endif /* _SDAP_H_ */
