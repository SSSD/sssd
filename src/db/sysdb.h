/*
   SSSD

   System Database Header

   Copyright (C) Simo Sorce <ssorce@redhat.com>	2008

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

#ifndef __SYS_DB_H__
#define __SYS_DB_H__

#include "util/util.h"
#include "confdb/confdb.h"
#include <tevent.h>

#define SYSDB_CONF_SECTION "config/sysdb"
#define CACHE_SYSDB_FILE "cache_%s.ldb"
#define LOCAL_SYSDB_FILE "sssd.ldb"

#define SYSDB_BASE "cn=sysdb"
#define SYSDB_DOM_BASE "cn=%s,cn=sysdb"
#define SYSDB_USERS_CONTAINER "cn=users"
#define SYSDB_GROUPS_CONTAINER "cn=groups"
#define SYSDB_CUSTOM_CONTAINER "cn=custom"
#define SYSDB_NETGROUP_CONTAINER "cn=Netgroups"
#define SYSDB_RANGE_CONTAINER "cn=ranges"
#define SYSDB_TMPL_USER_BASE SYSDB_USERS_CONTAINER",cn=%s,"SYSDB_BASE
#define SYSDB_TMPL_GROUP_BASE SYSDB_GROUPS_CONTAINER",cn=%s,"SYSDB_BASE
#define SYSDB_TMPL_CUSTOM_BASE SYSDB_CUSTOM_CONTAINER",cn=%s,"SYSDB_BASE
#define SYSDB_TMPL_NETGROUP_BASE SYSDB_NETGROUP_CONTAINER",cn=%s,"SYSDB_BASE
#define SYSDB_TMPL_RANGE_BASE SYSDB_RANGE_CONTAINER",cn=%s,"SYSDB_BASE

#define SYSDB_SUBDOMAIN_CLASS "subdomain"
#define SYSDB_RANGE_CLASS "idrange"
#define SYSDB_USER_CLASS "user"
#define SYSDB_GROUP_CLASS "group"
#define SYSDB_NETGROUP_CLASS "netgroup"
#define SYSDB_HOST_CLASS "host"
#define SYSDB_HOSTGROUP_CLASS "hostgroup"
#define SYSDB_SELINUX_USERMAP_CLASS "selinuxusermap"
#define SYSDB_SELINUX_CLASS "selinux"
#define SYSDB_ID_RANGE_CLASS "idRange"
#define SYSDB_DOMAIN_ID_RANGE_CLASS "domainIDRange"
#define SYSDB_TRUSTED_AD_DOMAIN_RANGE_CLASS "TrustedADDomainRange"

#define SYSDB_NAME "name"
#define SYSDB_NAME_ALIAS "nameAlias"
#define SYSDB_OBJECTCLASS "objectClass"

#define SYSDB_NEXTID "nextID"
#define SYSDB_UIDNUM "uidNumber"
#define SYSDB_GIDNUM "gidNumber"
#define SYSDB_CREATE_TIME "createTimestamp"


#define SYSDB_NAME "name"
#define SYSDB_NAME_ALIAS "nameAlias"
#define SYSDB_OBJECTCLASS "objectClass"

#define SYSDB_NEXTID "nextID"
#define SYSDB_UIDNUM "uidNumber"
#define SYSDB_GIDNUM "gidNumber"
#define SYSDB_CREATE_TIME "createTimestamp"

#define SYSDB_PWD "userPassword"
#define SYSDB_FULLNAME "fullName"
#define SYSDB_HOMEDIR "homeDirectory"
#define SYSDB_SHELL "loginShell"
#define SYSDB_MEMBEROF "memberOf"
#define SYSDB_DISABLED "disabled"

#define SYSDB_MEMBER "member"
#define SYSDB_MEMBERUID "memberUid"
#define SYSDB_GHOST "ghost"
#define SYSDB_POSIX "isPosix"
#define SYSDB_USER_CATEGORY "userCategory"
#define SYSDB_HOST_CATEGORY "hostCategory"

#define SYSDB_DEFAULTGROUP "defaultGroup"
#define SYSDB_GECOS "gecos"
#define SYSDB_LOCALE "locale"
#define SYSDB_KEYBOARD "keyboard"
#define SYSDB_SESSION "session"
#define SYSDB_LAST_LOGIN "lastLogin"
#define SYSDB_LAST_ONLINE_AUTH "lastOnlineAuth"
#define SYSDB_USERPIC "userPicture"
#define SYSDB_LAST_FAILED_LOGIN "lastFailedLogin"
#define SYSDB_FAILED_LOGIN_ATTEMPTS "failedLoginAttempts"

#define SYSDB_LAST_UPDATE "lastUpdate"
#define SYSDB_CACHE_EXPIRE "dataExpireTimestamp"
#define SYSDB_INITGR_EXPIRE "initgrExpireTimestamp"

#define SYSDB_AUTHORIZED_SERVICE "authorizedService"
#define SYSDB_AUTHORIZED_HOST "authorizedHost"

#define SYSDB_NETGROUP_TRIPLE "netgroupTriple"
#define SYSDB_ORIG_NETGROUP_MEMBER "originalMemberNisNetgroup"
#define SYSDB_ORIG_NETGROUP_EXTERNAL_HOST "originalExternalHost"
#define SYSDB_NETGROUP_DOMAIN "nisDomain"
#define SYSDB_NETGROUP_MEMBER "memberNisNetgroup"
#define SYSDB_DESCRIPTION   "description"

#define SYSDB_FQDN "fqdn"
#define SYSDB_SERVERHOSTNAME "serverHostname"

#define SYSDB_SELINUX_SEEALSO "seeAlso"
#define SYSDB_SELINUX_USER "selinuxUser"
#define SYSDB_SELINUX_ENABLED "enabled"
#define SYSDB_SELINUX_HOST_PRIORITY "hostPriority"

#define SYSDB_CACHEDPWD "cachedPassword"

#define SYSDB_UUID "uniqueID"
#define SYSDB_SID "objectSID"
#define SYSDB_PRIMARY_GROUP "ADPrimaryGroupID"
#define SYSDB_SID_STR "objectSIDString"
#define SYSDB_UPN "userPrincipalName"
#define SYSDB_CCACHE_FILE "ccacheFile"

#define SYSDB_ORIG_DN "originalDN"
#define SYSDB_ORIG_MODSTAMP "originalModifyTimestamp"
#define SYSDB_ORIG_MEMBEROF "originalMemberOf"
#define SYSDB_ORIG_MEMBER_USER "originalMemberUser"
#define SYSDB_ORIG_MEMBER_HOST "originalMemberHost"

#define SYSDB_USN "entryUSN"
#define SYSDB_HIGH_USN "highestUSN"

#define SYSDB_SSH_PUBKEY "sshPublicKey"

#define SYSDB_SUBDOMAIN_REALM "realmName"
#define SYSDB_SUBDOMAIN_FLAT "flatName"
#define SYSDB_SUBDOMAIN_ID "domainID"

#define SYSDB_BASE_ID "baseID"
#define SYSDB_ID_RANGE_SIZE "idRangeSize"
#define SYSDB_BASE_RID "baseRID"
#define SYSDB_SECONDARY_BASE_RID "secondaryBaseRID"
#define SYSDB_DOMAIN_ID "domainID"

#define SYSDB_NEXTID_FILTER "("SYSDB_NEXTID"=*)"

#define SYSDB_UC "objectclass="SYSDB_USER_CLASS
#define SYSDB_GC "objectclass="SYSDB_GROUP_CLASS
#define SYSDB_NC "objectclass="SYSDB_NETGROUP_CLASS
#define SYSDB_MPGC "|("SYSDB_UC")("SYSDB_GC")"

#define SYSDB_PWNAM_FILTER "(&("SYSDB_UC")(|("SYSDB_NAME_ALIAS"=%s)("SYSDB_NAME"=%s)))"
#define SYSDB_PWUID_FILTER "(&("SYSDB_UC")("SYSDB_UIDNUM"=%lu))"
#define SYSDB_PWENT_FILTER "("SYSDB_UC")"

#define SYSDB_GRNAM_FILTER "(&("SYSDB_GC")(|("SYSDB_NAME_ALIAS"=%s)("SYSDB_NAME"=%s)))"
#define SYSDB_GRNA2_FILTER "(&("SYSDB_UC")("SYSDB_MEMBEROF"=%s))"
#define SYSDB_GRGID_FILTER "(&("SYSDB_GC")("SYSDB_GIDNUM"=%lu))"
#define SYSDB_GRENT_FILTER "("SYSDB_GC")"
#define SYSDB_GRNAM_MPG_FILTER "(&("SYSDB_MPGC")(|("SYSDB_NAME_ALIAS"=%s)("SYSDB_NAME"=%s)))"
#define SYSDB_GRGID_MPG_FILTER "(&("SYSDB_MPGC")("SYSDB_GIDNUM"=%lu))"
#define SYSDB_GRENT_MPG_FILTER "("SYSDB_MPGC")"

#define SYSDB_INITGR_FILTER "(&("SYSDB_GC")("SYSDB_GIDNUM"=*))"

#define SYSDB_GETCACHED_FILTER "(&"SYSDB_UC")("SYSDB_LAST_LOGIN">=%lu))"

#define SYSDB_NETGR_FILTER "(&("SYSDB_NC")(|("SYSDB_NAME_ALIAS"=%s)("SYSDB_NAME"=%s)))"
#define SYSDB_NETGR_TRIPLES_FILTER "(|("SYSDB_NAME"=%s)("SYSDB_NAME_ALIAS"=%s)("SYSDB_MEMBEROF"=%s))"

#define SYSDB_HAS_ENUMERATED "has_enumerated"

#define SYSDB_DEFAULT_ATTRS SYSDB_LAST_UPDATE, \
                            SYSDB_CACHE_EXPIRE, \
                            SYSDB_INITGR_EXPIRE, \
                            SYSDB_OBJECTCLASS

#define SYSDB_PW_ATTRS {SYSDB_NAME, SYSDB_UIDNUM, \
                        SYSDB_GIDNUM, SYSDB_GECOS, \
                        SYSDB_HOMEDIR, SYSDB_SHELL, \
                        SYSDB_DEFAULT_ATTRS, \
                        NULL}
#define SYSDB_GRSRC_ATTRS {SYSDB_NAME, SYSDB_GIDNUM, \
                           SYSDB_MEMBERUID, \
                           SYSDB_GHOST, \
                           SYSDB_DEFAULT_ATTRS, \
                           NULL}
#define SYSDB_GRPW_ATTRS {SYSDB_NAME, SYSDB_UIDNUM, \
                          SYSDB_DEFAULT_ATTRS, \
                          NULL}
#define SYSDB_GRENT_ATTRS {SYSDB_NAME, SYSDB_UIDNUM, SYSDB_MEMBEROF, \
                           SYSDB_DEFAULT_ATTRS, \
                           NULL}

#define SYSDB_NETGR_ATTRS {SYSDB_NAME, SYSDB_NETGROUP_TRIPLE, \
                           SYSDB_NETGROUP_MEMBER, \
                           SYSDB_DEFAULT_ATTRS, \
                           NULL}

#define SYSDB_INITGR_ATTR SYSDB_MEMBEROF
#define SYSDB_INITGR_ATTRS {SYSDB_GIDNUM, SYSDB_POSIX, \
                            SYSDB_DEFAULT_ATTRS, \
                            NULL}

#define SYSDB_TMPL_USER SYSDB_NAME"=%s,"SYSDB_TMPL_USER_BASE
#define SYSDB_TMPL_GROUP SYSDB_NAME"=%s,"SYSDB_TMPL_GROUP_BASE
#define SYSDB_TMPL_NETGROUP SYSDB_NAME"=%s,"SYSDB_TMPL_NETGROUP_BASE
#define SYSDB_TMPL_CUSTOM_SUBTREE "cn=%s,"SYSDB_TMPL_CUSTOM_BASE
#define SYSDB_TMPL_CUSTOM SYSDB_NAME"=%s,cn=%s,"SYSDB_TMPL_CUSTOM_BASE
#define SYSDB_TMPL_RANGE SYSDB_NAME"=%s,"SYSDB_TMPL_RANGE_BASE

#define SYSDB_MOD_ADD LDB_FLAG_MOD_ADD
#define SYSDB_MOD_DEL LDB_FLAG_MOD_DELETE
#define SYSDB_MOD_REP LDB_FLAG_MOD_REPLACE

struct confdb_ctx;
struct sysdb_ctx;

struct sysdb_ctx_list {
    struct sysdb_ctx **dbs;
    size_t num_dbs;

    char *db_path;
};

struct sysdb_attrs {
    int num;
    struct ldb_message_element *a;
};

/* sysdb_attrs helper functions */
struct sysdb_attrs *sysdb_new_attrs(TALLOC_CTX *mem_ctx);

struct sysdb_subdom {
    const char *realm;
    const char *name;
    const char *flat_name;
    const char *id;
};

struct range_info {
    char *name;
    uint32_t base_id;
    uint32_t id_range_size;
    uint32_t base_rid;
    uint32_t secondary_base_rid;
    char *trusted_dom_sid;
};


/* values are copied in the structure, allocated on "attrs" */
int sysdb_attrs_add_val(struct sysdb_attrs *attrs,
                        const char *name, const struct ldb_val *val);
int sysdb_attrs_add_string(struct sysdb_attrs *attrs,
                           const char *name, const char *str);
int sysdb_attrs_add_bool(struct sysdb_attrs *attrs,
                         const char *name, bool value);
int sysdb_attrs_add_long(struct sysdb_attrs *attrs,
                         const char *name, long value);
int sysdb_attrs_add_uint32(struct sysdb_attrs *attrs,
                           const char *name, uint32_t value);
int sysdb_attrs_add_time_t(struct sysdb_attrs *attrs,
                           const char *name, time_t value);
int sysdb_attrs_copy_values(struct sysdb_attrs *src,
                            struct sysdb_attrs *dst,
                            const char *name);
int sysdb_attrs_get_el(struct sysdb_attrs *attrs, const char *name,
                       struct ldb_message_element **el);
int sysdb_attrs_steal_string(struct sysdb_attrs *attrs,
                             const char *name, char *str);
int sysdb_attrs_get_string(struct sysdb_attrs *attrs, const char *name,
                           const char **string);
int sysdb_attrs_get_string_array(struct sysdb_attrs *attrs, const char *name,
                                 TALLOC_CTX *mem_ctx, const char ***string);
errno_t sysdb_attrs_get_bool(struct sysdb_attrs *attrs, const char *name,
                             bool *value);
int sysdb_attrs_get_uint16_t(struct sysdb_attrs *attrs, const char *name,
                             uint16_t *value);
int sysdb_attrs_get_uint32_t(struct sysdb_attrs *attrs, const char *name,
                             uint32_t *value);

int sysdb_attrs_replace_name(struct sysdb_attrs *attrs, const char *oldname,
                                 const char *newname);

int sysdb_attrs_users_from_str_list(struct sysdb_attrs *attrs,
                                    const char *attr_name,
                                    const char *domain,
                                    const char *const *list);
errno_t sysdb_attrs_primary_name(struct sysdb_ctx *sysdb,
                                 struct sysdb_attrs *attrs,
                                 const char *ldap_attr,
                                 const char **_primary);
errno_t sysdb_attrs_get_aliases(TALLOC_CTX *mem_ctx,
                                struct sysdb_attrs *attrs,
                                const char *primary,
                                bool lowercase,
                                const char ***_aliases);
errno_t sysdb_attrs_primary_name_list(struct sysdb_ctx *sysdb,
                                      TALLOC_CTX *mem_ctx,
                                      struct sysdb_attrs **attr_list,
                                      size_t attr_count,
                                      const char *ldap_attr,
                                      char ***name_list);
errno_t sysdb_get_real_name(TALLOC_CTX *mem_ctx,
                            struct sysdb_ctx *sysdb,
                            const char *name,
                            const char **_cname);

errno_t sysdb_msg2attrs(TALLOC_CTX *mem_ctx, size_t count,
                        struct ldb_message **msgs,
                        struct sysdb_attrs ***attrs);

/* convert an ldb error into an errno error */
int sysdb_error_to_errno(int ldberr);

/* DNs related helper functions */
errno_t sysdb_get_rdn(struct sysdb_ctx *sysdb, void *mem_ctx,
                      const char *_dn, char **_name, char **_val);
struct ldb_dn *sysdb_user_dn(struct sysdb_ctx *sysdb, void *mem_ctx,
                             const char *domain, const char *name);
struct ldb_dn *sysdb_group_dn(struct sysdb_ctx *sysdb, void *mem_ctx,
                              const char *domain, const char *name);
struct ldb_dn *sysdb_netgroup_dn(struct sysdb_ctx *sysdb, void *mem_ctx,
                                 const char *domain, const char *name);
struct ldb_dn *sysdb_netgroup_base_dn(struct sysdb_ctx *sysdb, void *mem_ctx,
                                      const char *domain);
errno_t sysdb_group_dn_name(struct sysdb_ctx *sysdb, void *mem_ctx,
                            const char *dn_str, char **name);
struct ldb_dn *sysdb_domain_dn(struct sysdb_ctx *sysdb, void *mem_ctx,
                               const char *domain);
struct ldb_dn *sysdb_custom_dn(struct sysdb_ctx *sysdb, void *mem_ctx,
                                const char *domain, const char *object_name,
                                const char *subtree_name);
struct ldb_dn *sysdb_custom_subtree_dn(struct sysdb_ctx *sysdb, void *mem_ctx,
                                       const char *domain,
                                       const char *subtree_name);

char *sysdb_user_strdn(TALLOC_CTX *mem_ctx,
                       const char *domain, const char *name);
char *sysdb_group_strdn(TALLOC_CTX *mem_ctx,
                        const char *domain, const char *name);


struct ldb_context *sysdb_ctx_get_ldb(struct sysdb_ctx *sysdb);

struct sss_domain_info *sysdb_ctx_get_domain(struct sysdb_ctx *sysdb);

int compare_ldb_dn_comp_num(const void *m1, const void *m2);

/* functions to start and finish transactions */
int sysdb_transaction_start(struct sysdb_ctx *sysdb);
int sysdb_transaction_commit(struct sysdb_ctx *sysdb);
int sysdb_transaction_cancel(struct sysdb_ctx *sysdb);

/* functions related to subdomains */
errno_t sysdb_get_subdomains(TALLOC_CTX *mem_ctx,
                             struct sysdb_ctx *sysdb,
                             size_t *subdomain_count,
                             struct sysdb_subdom ***subdomain_list);

errno_t sysdb_domain_create(struct sysdb_ctx *sysdb, const char *domain_name);

errno_t sysdb_update_subdomains(struct sysdb_ctx *sysdb,
                                int num_subdoms,
                                struct sysdb_subdom *subdoms);

errno_t sysdb_get_subdomain_context(TALLOC_CTX *mem_ctx,
                                    struct sysdb_ctx *sysdb,
                                    struct sss_domain_info *subdomain,
                                    struct sysdb_ctx **subdomain_ctx);

errno_t sysdb_master_domain_get_info(TALLOC_CTX *mem_ctx,
                                     struct sysdb_ctx *sysdb,
                                     struct sysdb_subdom **info);

errno_t sysdb_master_domain_add_info(struct sysdb_ctx *sysdb,
                                     struct sysdb_subdom *domain_info);


errno_t sysdb_search_domuser_by_name(TALLOC_CTX *mem_ctx,
                                     struct sss_domain_info *domain,
                                     const char *name,
                                     const char **attrs,
                                     struct ldb_message **msg);
errno_t sysdb_search_domuser_by_uid(TALLOC_CTX *mem_ctx,
                                    struct sss_domain_info *domain,
                                    uid_t uid,
                                    const char **attrs,
                                    struct ldb_message **msg);
errno_t sysdb_store_domuser(struct sss_domain_info *domain,
                            const char *name,
                            const char *pwd,
                            uid_t uid, gid_t gid,
                            const char *gecos,
                            const char *homedir,
                            const char *shell,
                            struct sysdb_attrs *attrs,
                            char **remove_attrs,
                            uint64_t cache_timeout,
                            time_t now);
errno_t sysdb_delete_domuser(struct sss_domain_info *domain,
                             const char *name, uid_t uid);


errno_t sysdb_search_domgroup_by_name(TALLOC_CTX *mem_ctx,
                                      struct sss_domain_info *domain,
                                      const char *name,
                                      const char **attrs,
                                      struct ldb_message **msg);
errno_t sysdb_search_domgroup_by_gid(TALLOC_CTX *mem_ctx,
                                     struct sss_domain_info *domain,
                                     gid_t gid,
                                     const char **attrs,
                                     struct ldb_message **msg);
errno_t sysdb_store_domgroup(struct sss_domain_info *domain,
                             const char *name,
                             gid_t gid,
                             struct sysdb_attrs *attrs,
                             uint64_t cache_timeout,
                             time_t now);
errno_t sysdb_delete_domgroup(struct sss_domain_info *domain,
                              const char *name, gid_t gid);

errno_t sysdb_get_ranges(TALLOC_CTX *mem_ctx, struct sysdb_ctx *sysdb,
                             size_t *range_count,
                             struct range_info ***range_list);
errno_t sysdb_range_create(struct sysdb_ctx *sysdb, struct range_info *range);
errno_t sysdb_update_ranges(struct sysdb_ctx *sysdb,
                            struct range_info **ranges);

/* Sysdb initialization.
 * call this function *only* once to initialize the database and get
 * the sysdb ctx */
int sysdb_init(TALLOC_CTX *mem_ctx,
               struct confdb_ctx *cdb,
               const char *alt_db_path,
               bool allow_upgrade,
               struct sysdb_ctx_list **_ctx_list);
/* used to initialize only one domain database.
 * Do NOT use if sysdb_init has already been called */
int sysdb_domain_init(TALLOC_CTX *mem_ctx,
                      struct sss_domain_info *domain,
                      const char *db_path,
                      struct sysdb_ctx **_ctx);

errno_t sysdb_init_domain_and_sysdb(TALLOC_CTX *mem_ctx,
                                    struct confdb_ctx *cdb,
                                    const char *domain_name,
                                    const char *db_path,
                                    struct sss_domain_info **_domain,
                                    struct sysdb_ctx **_ctx);

int sysdb_list_init(TALLOC_CTX *mem_ctx,
                    const char *path,
                    struct sysdb_ctx *sysdb,
                    struct sysdb_ctx_list **_list);

errno_t sysdb_add_to_domain(struct sss_domain_info *domain,
                            struct sysdb_ctx *ctx);
/* functions to retrieve information from sysdb
 * These functions automatically starts an operation
 * therefore they cannot be called within a transaction */
int sysdb_getpwnam(TALLOC_CTX *mem_ctx,
                   struct sysdb_ctx *sysdb,
                   const char *name,
                   struct ldb_result **res);

int sysdb_getpwuid(TALLOC_CTX *mem_ctx,
                   struct sysdb_ctx *sysdb,
                   uid_t uid,
                   struct ldb_result **res);

int sysdb_enumpwent(TALLOC_CTX *mem_ctx,
                    struct sysdb_ctx *sysdb,
                    struct ldb_result **res);

int sysdb_getgrnam(TALLOC_CTX *mem_ctx,
                   struct sysdb_ctx *sysdb,
                   const char *name,
                   struct ldb_result **res);

int sysdb_getgrgid(TALLOC_CTX *mem_ctx,
                   struct sysdb_ctx *sysdb,
                   gid_t gid,
                   struct ldb_result **res);

int sysdb_enumgrent(TALLOC_CTX *mem_ctx,
                    struct sysdb_ctx *sysdb,
                    struct ldb_result **res);

struct sysdb_netgroup_ctx {
    enum {SYSDB_NETGROUP_TRIPLE_VAL, SYSDB_NETGROUP_GROUP_VAL} type;
    union {
        struct {
            char *hostname;
            char *username;
            char *domainname;
        } triple;
        char *groupname;
    } value;
};

errno_t sysdb_getnetgr(TALLOC_CTX *mem_ctx,
                       struct sysdb_ctx *sysdb,
                       const char *netgroup,
                       struct ldb_result **res);

int sysdb_initgroups(TALLOC_CTX *mem_ctx,
                     struct sysdb_ctx *sysdb,
                     const char *name,
                     struct ldb_result **res);

int sysdb_get_user_attr(TALLOC_CTX *mem_ctx,
                        struct sysdb_ctx *sysdb,
                        const char *name,
                        const char **attributes,
                        struct ldb_result **res);

int sysdb_get_netgroup_attr(TALLOC_CTX *mem_ctx,
                            struct sysdb_ctx *sysdb,
                            const char *netgrname,
                            const char **attributes,
                            struct ldb_result **res);

/* functions that modify the databse
 * they have to be called within a transaction
 * See sysdb_transaction_send()/_recv() */

/* Delete Entry */
int sysdb_delete_entry(struct sysdb_ctx *sysdb,
                       struct ldb_dn *dn,
                       bool ignore_not_found);


int sysdb_delete_recursive(struct sysdb_ctx *sysdb,
                           struct ldb_dn *dn,
                           bool ignore_not_found);

/* Search Entry */
int sysdb_search_entry(TALLOC_CTX *mem_ctx,
                       struct sysdb_ctx *sysdb,
                       struct ldb_dn *base_dn,
                       int scope,
                       const char *filter,
                       const char **attrs,
                       size_t *msgs_count,
                       struct ldb_message ***msgs);

/* Search User (by uid or name) */
int sysdb_search_user_by_name(TALLOC_CTX *mem_ctx,
                              struct sysdb_ctx *sysdb,
                              const char *name,
                              const char **attrs,
                              struct ldb_message **msg);

int sysdb_search_user_by_uid(TALLOC_CTX *mem_ctx,
                             struct sysdb_ctx *sysdb,
                             uid_t uid,
                             const char **attrs,
                             struct ldb_message **msg);

/* Search Group (by gid or name) */
int sysdb_search_group_by_name(TALLOC_CTX *mem_ctx,
                               struct sysdb_ctx *sysdb,
                               const char *name,
                               const char **attrs,
                               struct ldb_message **msg);

int sysdb_search_group_by_gid(TALLOC_CTX *mem_ctx,
                              struct sysdb_ctx *sysdb,
                              gid_t gid,
                              const char **attrs,
                              struct ldb_message **msg);

/* Search Netgroup (by name) */
int sysdb_search_netgroup_by_name(TALLOC_CTX *mem_ctx,
                                  struct sysdb_ctx *sysdb,
                                  const char *name,
                                  const char **attrs,
                                  struct ldb_message **msg);

/* Replace entry attrs */
int sysdb_set_entry_attr(struct sysdb_ctx *sysdb,
                         struct ldb_dn *entry_dn,
                         struct sysdb_attrs *attrs,
                         int mod_op);

/* Replace user attrs */
int sysdb_set_user_attr(struct sysdb_ctx *sysdb,
                        const char *name,
                        struct sysdb_attrs *attrs,
                        int mod_op);

/* Replace group attrs */
int sysdb_set_group_attr(struct sysdb_ctx *sysdb,
                         const char *name,
                         struct sysdb_attrs *attrs,
                         int mod_op);

/* Replace netgroup attrs */
int sysdb_set_netgroup_attr(struct sysdb_ctx *sysdb,
                            const char *name,
                            struct sysdb_attrs *attrs,
                            int mod_op);

/* Allocate a new id */
int sysdb_get_new_id(struct sysdb_ctx *sysdb,
                     uint32_t *id);

/* Add user (only basic attrs and w/o checks) */
int sysdb_add_basic_user(struct sysdb_ctx *sysdb,
                         const char *name,
                         uid_t uid, gid_t gid,
                         const char *gecos,
                         const char *homedir,
                         const char *shell);

/* Add user (all checks) */
int sysdb_add_user(struct sysdb_ctx *sysdb,
                   const char *name,
                   uid_t uid, gid_t gid,
                   const char *gecos,
                   const char *homedir,
                   const char *shell,
                   struct sysdb_attrs *attrs,
                   int cache_timeout,
                   time_t now);

/* Add group (only basic attrs and w/o checks) */
int sysdb_add_basic_group(struct sysdb_ctx *sysdb,
                          const char *name, gid_t gid);

/* Add group (all checks) */
int sysdb_add_group(struct sysdb_ctx *sysdb,
                    const char *name, gid_t gid,
                    struct sysdb_attrs *attrs,
                    int cache_timeout,
                    time_t now);

int sysdb_add_incomplete_group(struct sysdb_ctx *sysdb,
                               const char *name,
                               gid_t gid,
                               const char *original_dn, bool posix,
                               time_t now);

/* Add netgroup (only basic attrs and w/o checks) */
int sysdb_add_basic_netgroup(struct sysdb_ctx *sysdb,
                             const char *name, const char *description);

int sysdb_add_netgroup(struct sysdb_ctx *sysdb,
                       const char *name,
                       const char *description,
                       struct sysdb_attrs *attrs,
                       char **missing,
                       int cache_timeout,
                       time_t now);

/* mod_op must be either LDB_FLAG_MOD_ADD or LDB_FLAG_MOD_DELETE */
int sysdb_mod_group_member(struct sysdb_ctx *sysdb,
                           struct ldb_dn *member_dn,
                           struct ldb_dn *group_dn,
                           int mod_op);

int sysdb_store_user(struct sysdb_ctx *sysdb,
                     const char *name,
                     const char *pwd,
                     uid_t uid, gid_t gid,
                     const char *gecos,
                     const char *homedir,
                     const char *shell,
                     struct sysdb_attrs *attrs,
                     char **remove_attrs,
                     uint64_t cache_timeout,
                     time_t now);

int sysdb_store_group(struct sysdb_ctx *sysdb,
                      const char *name,
                      gid_t gid,
                      struct sysdb_attrs *attrs,
                      uint64_t cache_timeout,
                      time_t now);

enum sysdb_member_type {
    SYSDB_MEMBER_USER,
    SYSDB_MEMBER_GROUP,
    SYSDB_MEMBER_NETGROUP,
    SYSDB_MEMBER_SERVICE,
    SYSDB_MEMBER_AUTOFSENTRY
};

int sysdb_add_group_member(struct sysdb_ctx *sysdb,
                           const char *group,
                           const char *member,
                           enum sysdb_member_type type);

int sysdb_remove_group_member(struct sysdb_ctx *sysdb,
                              const char *group,
                              const char *member,
                              enum sysdb_member_type type);

errno_t sysdb_update_members(struct sysdb_ctx *sysdb,
                             const char *member,
                             enum sysdb_member_type type,
                             const char *const *add_groups,
                             const char *const *del_groups);

errno_t sysdb_add_netgroup_tuple(struct sysdb_ctx *sysdb,
                                 const char *netgroup,
                                 const char *hostname,
                                 const char *username,
                                 const char *domainname);

errno_t sysdb_remove_netgroup_tuple(struct sysdb_ctx *sysdb,
                                    const char *netgroup,
                                    const char *hostname,
                                    const char *username,
                                    const char *domainname);

errno_t sysdb_mod_netgroup_tuple(struct sysdb_ctx *sysdb,
                                 const char *netgroup,
                                 const char *hostname,
                                 const char *username,
                                 const char *domainname,
                                 int mod_op);

errno_t sysdb_add_netgroup_member(struct sysdb_ctx *sysdb,
                                  const char *netgroup,
                                  const char *member_netgroup);

errno_t sysdb_remove_netgroup_member(struct sysdb_ctx *sysdb,
                                     const char *netgroup,
                                     const char *member_netgroup);

errno_t sysdb_mod_netgroup_member(struct sysdb_ctx *sysdb,
                                  const char *netgroup,
                                  const char *member_netgroup,
                                  int mod_op);

/* Password caching function.
 * If you are in a transaction ignore sysdb and pass in the handle.
 * If you are not in a transaction pass NULL in handle and provide sysdb,
 * in this case a transaction will be automatically started and the
 * function will be completely wrapped in it's own sysdb transaction */
int sysdb_cache_password(struct sysdb_ctx *sysdb,
                         const char *username,
                         const char *password);

errno_t check_failed_login_attempts(struct confdb_ctx *cdb,
                                    struct ldb_message *ldb_msg,
                                    uint32_t *failed_login_attempts,
                                    time_t *delayed_until);
int sysdb_cache_auth(struct sysdb_ctx *sysdb,
                     const char *name,
                     const uint8_t *authtok,
                     size_t authtok_size,
                     struct confdb_ctx *cdb,
                     bool just_check,
                     time_t *_expire_date,
                     time_t *_delayed_until);

int sysdb_store_custom(struct sysdb_ctx *sysdb,
                       const char *object_name,
                       const char *subtree_name,
                       struct sysdb_attrs *attrs);

int sysdb_search_custom(TALLOC_CTX *mem_ctx,
                        struct sysdb_ctx *sysdb,
                        const char *filter,
                        const char *subtree_name,
                        const char **attrs,
                        size_t *msgs_count,
                        struct ldb_message ***msgs);

int sysdb_search_custom_by_name(TALLOC_CTX *mem_ctx,
                                struct sysdb_ctx *sysdb,
                                const char *object_name,
                                const char *subtree_name,
                                const char **attrs,
                                size_t *_count,
                                struct ldb_message ***_msgs);

int sysdb_delete_custom(struct sysdb_ctx *sysdb,
                        const char *object_name,
                        const char *subtree_name);

int sysdb_asq_search(TALLOC_CTX *mem_ctx,
                     struct sysdb_ctx *sysdb,
                     struct ldb_dn *base_dn,
                     const char *expression,
                     const char *asq_attribute,
                     const char **attrs,
                     size_t *msgs_count,
                     struct ldb_message ***msgs);

int sysdb_search_users(TALLOC_CTX *mem_ctx,
                       struct sysdb_ctx *sysdb,
                       const char *sub_filter,
                       const char **attrs,
                       size_t *msgs_count,
                       struct ldb_message ***msgs);

int sysdb_delete_user(struct sysdb_ctx *sysdb,
                      const char *name, uid_t uid);

int sysdb_search_groups(TALLOC_CTX *mem_ctx,
                        struct sysdb_ctx *sysdb,
                        const char *sub_filter,
                        const char **attrs,
                        size_t *msgs_count,
                        struct ldb_message ***msgs);

int sysdb_delete_group(struct sysdb_ctx *sysdb,
                       const char *name, gid_t gid);

int sysdb_search_netgroups(TALLOC_CTX *mem_ctx,
                           struct sysdb_ctx *sysdb,
                           const char *sub_filter,
                           const char **attrs,
                           size_t *msgs_count,
                           struct ldb_message ***msgs);

int sysdb_delete_netgroup(struct sysdb_ctx *sysdb,
                          const char *name);

errno_t sysdb_attrs_to_list(TALLOC_CTX *mem_ctx,
                            struct sysdb_attrs **attrs,
                            int attr_count,
                            const char *attr_name,
                            char ***_list);

errno_t sysdb_netgr_to_entries(TALLOC_CTX *mem_ctx,
                               struct ldb_result *res,
                               struct sysdb_netgroup_ctx ***entries);

errno_t sysdb_dn_sanitize(void *mem_ctx, const char *input,
                          char **sanitized);

errno_t sysdb_get_bool(struct sysdb_ctx *sysdb,
                       struct ldb_dn *dn,
                       const char *attr_name,
                       bool *value);

errno_t sysdb_set_bool(struct sysdb_ctx *sysdb,
                       struct ldb_dn *dn,
                       const char *cn_value,
                       const char *attr_name,
                       bool value);

errno_t sysdb_has_enumerated(struct sysdb_ctx *sysdb,
                             bool *has_enumerated);

errno_t sysdb_set_enumerated(struct sysdb_ctx *sysdb,
                             bool enumerated);

errno_t sysdb_remove_attrs(struct sysdb_ctx *sysdb,
                           const char *name,
                           enum sysdb_member_type type,
                           char **remove_attrs);

errno_t sysdb_get_direct_parents(TALLOC_CTX *mem_ctx,
                                 struct sysdb_ctx *sysdb,
                                 struct sss_domain_info *dom,
                                 enum sysdb_member_type mtype,
                                 const char *name,
                                 char ***_direct_parents);

/* === Functions related to ID-mapping === */

#define SYSDB_IDMAP_CONTAINER "cn=id_mappings"

#define SYSDB_IDMAP_SUBTREE "idmap"
#define SYSDB_IDMAP_MAPPING_OC "id_mapping"
#define SYSDB_IDMAP_FILTER "(objectClass="SYSDB_IDMAP_MAPPING_OC")"
#define SYSDB_IDMAP_SID_ATTR "objectSID"
#define SYSDB_IDMAP_SLICE_ATTR "slice"

#define SYSDB_IDMAP_ATTRS { \
    SYSDB_NAME, \
    SYSDB_IDMAP_SID_ATTR, \
    SYSDB_IDMAP_SLICE_ATTR, \
    NULL }

#define SYSDB_TMPL_IDMAP_BASE SYSDB_IDMAP_CONTAINER",cn=%s,"SYSDB_BASE
#define SYSDB_TMPL_IDMAP SYSDB_IDMAP_SID_ATTR"=%s,"SYSDB_TMPL_IDMAP_BASE

struct ldb_dn *sysdb_idmap_dn(TALLOC_CTX *mem_ctx, struct sysdb_ctx *sysdb,
                              const char *object_sid);

errno_t sysdb_idmap_store_mapping(struct sysdb_ctx *sysdb,
                                  const char *dom_name,
                                  const char *dom_sid,
                                  id_t slice_num);

errno_t sysdb_idmap_get_mappings(TALLOC_CTX *mem_ctx,
                                 struct sysdb_ctx *sysdb,
                                 struct ldb_result **_result);

#endif /* __SYS_DB_H__ */
