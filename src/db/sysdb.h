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
#define SYSDB_TMPL_USER_BASE SYSDB_USERS_CONTAINER",cn=%s,"SYSDB_BASE
#define SYSDB_TMPL_GROUP_BASE SYSDB_GROUPS_CONTAINER",cn=%s,"SYSDB_BASE
#define SYSDB_TMPL_CUSTOM_BASE SYSDB_CUSTOM_CONTAINER",cn=%s,"SYSDB_BASE

#define SYSDB_USER_CLASS "user"
#define SYSDB_GROUP_CLASS "group"

#define SYSDB_NAME "name"

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

#define SYSDB_CACHEDPWD "cachedPassword"

#define SYSDB_UUID "uniqueID"
#define SYSDB_UPN "userPrincipalName"
#define SYSDB_CCACHE_FILE "ccacheFile"

#define SYSDB_ORIG_DN "originalDN"
#define SYSDB_ORIG_MODSTAMP "originalModifyTimestamp"
#define SYSDB_ORIG_MEMBEROF "originalMemberOf"

#define SYSDB_USN "entryUSN"
#define SYSDB_HIGH_USN "highestUSN"

#define SYSDB_NEXTID_FILTER "("SYSDB_NEXTID"=*)"

#define SYSDB_UC "objectclass="SYSDB_USER_CLASS
#define SYSDB_GC "objectclass="SYSDB_GROUP_CLASS
#define SYSDB_MPGC "|("SYSDB_UC")("SYSDB_GC")"

#define SYSDB_PWNAM_FILTER "(&("SYSDB_UC")("SYSDB_NAME"=%s))"
#define SYSDB_PWUID_FILTER "(&("SYSDB_UC")("SYSDB_UIDNUM"=%lu))"
#define SYSDB_PWENT_FILTER "("SYSDB_UC")"

#define SYSDB_GRNAM_FILTER "(&("SYSDB_GC")("SYSDB_NAME"=%s))"
#define SYSDB_GRNA2_FILTER "(&("SYSDB_UC")("SYSDB_MEMBEROF"=%s))"
#define SYSDB_GRGID_FILTER "(&("SYSDB_GC")("SYSDB_GIDNUM"=%lu))"
#define SYSDB_GRENT_FILTER "("SYSDB_GC")"
#define SYSDB_GRNAM_MPG_FILTER "(&("SYSDB_MPGC")("SYSDB_NAME"=%s))"
#define SYSDB_GRGID_MPG_FILTER "(&("SYSDB_MPGC")("SYSDB_GIDNUM"=%lu))"
#define SYSDB_GRENT_MPG_FILTER "("SYSDB_MPGC")"

#define SYSDB_INITGR_FILTER "(&("SYSDB_GC")("SYSDB_GIDNUM"=*))"

#define SYSDB_GETCACHED_FILTER "(&"SYSDB_UC")("SYSDB_LAST_LOGIN">=%lu))"

#define SYSDB_DEFAULT_ATTRS SYSDB_LAST_UPDATE, \
                            SYSDB_CACHE_EXPIRE, \
                            SYSDB_INITGR_EXPIRE, \
                            "objectClass"

#define SYSDB_PW_ATTRS {SYSDB_NAME, SYSDB_UIDNUM, \
                        SYSDB_GIDNUM, SYSDB_GECOS, \
                        SYSDB_HOMEDIR, SYSDB_SHELL, \
                        SYSDB_DEFAULT_ATTRS, \
                        NULL}
#define SYSDB_GRSRC_ATTRS {SYSDB_NAME, SYSDB_GIDNUM, \
                           SYSDB_MEMBERUID, \
                           SYSDB_DEFAULT_ATTRS, \
                           NULL}
#define SYSDB_GRPW_ATTRS {SYSDB_NAME, SYSDB_UIDNUM, \
                          SYSDB_DEFAULT_ATTRS, \
                          NULL}
#define SYSDB_GRENT_ATTRS {SYSDB_NAME, SYSDB_UIDNUM, SYSDB_MEMBEROF, \
                           SYSDB_DEFAULT_ATTRS, \
                           NULL}

#define SYSDB_INITGR_ATTR SYSDB_MEMBEROF
#define SYSDB_INITGR_ATTRS {SYSDB_GIDNUM, \
                            SYSDB_DEFAULT_ATTRS, \
                            NULL}

#define SYSDB_TMPL_USER SYSDB_NAME"=%s,"SYSDB_TMPL_USER_BASE
#define SYSDB_TMPL_GROUP SYSDB_NAME"=%s,"SYSDB_TMPL_GROUP_BASE
#define SYSDB_TMPL_CUSTOM_SUBTREE "cn=%s,"SYSDB_TMPL_CUSTOM_BASE
#define SYSDB_TMPL_CUSTOM SYSDB_NAME"=%s,cn=%s,"SYSDB_TMPL_CUSTOM_BASE

#define SYSDB_MOD_ADD LDB_FLAG_MOD_ADD
#define SYSDB_MOD_DEL LDB_FLAG_MOD_DELETE
#define SYSDB_MOD_REP LDB_FLAG_MOD_REPLACE

struct confdb_ctx;
struct sysdb_ctx_list;
struct sysdb_ctx;
struct sysdb_handle;

struct sysdb_attrs {
    int num;
    struct ldb_message_element *a;
};

/* sysdb_attrs helper functions */
struct sysdb_attrs *sysdb_new_attrs(TALLOC_CTX *memctx);

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
int sysdb_attrs_get_el(struct sysdb_attrs *attrs, const char *name,
                       struct ldb_message_element **el);
int sysdb_attrs_steal_string(struct sysdb_attrs *attrs,
                             const char *name, char *str);
int sysdb_attrs_get_string(struct sysdb_attrs *attrs, const char *name,
                           const char **string);
int sysdb_attrs_get_string_array(struct sysdb_attrs *attrs, const char *name,
                                 TALLOC_CTX *mem_ctx, const char ***string);

int sysdb_attrs_replace_name(struct sysdb_attrs *attrs, const char *oldname,
                                 const char *newname);

int sysdb_attrs_users_from_str_list(struct sysdb_attrs *attrs,
                                    const char *attr_name,
                                    const char *domain,
                                    const char **list);
int sysdb_attrs_users_from_ldb_vals(struct sysdb_attrs *attrs,
                                    const char *attr_name,
                                    const char *domain,
                                    struct ldb_val *values,
                                    int num_values);

/* convert an ldb error into an errno error */
int sysdb_error_to_errno(int ldberr);

/* DNs related helper functions */
struct ldb_dn *sysdb_user_dn(struct sysdb_ctx *ctx, void *memctx,
                             const char *domain, const char *name);
struct ldb_dn *sysdb_group_dn(struct sysdb_ctx *ctx, void *memctx,
                              const char *domain, const char *name);
errno_t sysdb_group_dn_name(struct sysdb_ctx *ctx, void *memctx,
                            const char *dn_str, char **name);
struct ldb_dn *sysdb_domain_dn(struct sysdb_ctx *ctx, void *memctx,
                               const char *domain);
struct ldb_dn *sysdb_custom_dn(struct sysdb_ctx *ctx, void *memctx,
                                const char *domain, const char *object_name,
                                const char *subtree_name);
struct ldb_dn *sysdb_custom_subtree_dn(struct sysdb_ctx *ctx, void *memctx,
                                       const char *domain,
                                       const char *subtree_name);

char *sysdb_user_strdn(TALLOC_CTX *memctx,
                       const char *domain, const char *name);
char *sysdb_group_strdn(TALLOC_CTX *memctx,
                        const char *domain, const char *name);


struct ldb_context *sysdb_ctx_get_ldb(struct sysdb_ctx *ctx);
struct ldb_context *sysdb_handle_get_ldb(struct sysdb_handle *handle);
struct sysdb_ctx *sysdb_handle_get_ctx(struct sysdb_handle *handle);

int compare_ldb_dn_comp_num(const void *m1, const void *m2);

/* function to start and finish a transaction
 * sysdb_transaction_send() will queue a request for a transaction
 * when it is done it will call the tevent_req callback, which must
 * retrieve the transaction handle using sysdb_transaction_recv()
 *
 * A transaction must be completed either by sending a commit:
 * sysdb_transaction_commit_send()/sysdb_transaction_commit_recv()
 * or by freeing the transaction handle (this will implicitly cause
 * a transaction cancelation).
 *
 * Transactions are serialized, no other transaction or operation can be
 * performed while a transaction is active. Multiple transaction request
 * are queued internally and served in order.
 */

struct tevent_req *sysdb_transaction_send(TALLOC_CTX *mem_ctx,
                                          struct tevent_context *ev,
                                          struct sysdb_ctx *ctx);
int sysdb_transaction_recv(struct tevent_req *req, TALLOC_CTX *memctx,
                           struct sysdb_handle **handle);

struct tevent_req *sysdb_transaction_commit_send(TALLOC_CTX *mem_ctx,
                                                 struct tevent_context *ev,
                                                 struct sysdb_handle *handle);
int sysdb_transaction_commit_recv(struct tevent_req *req);


/* default transaction commit receive function.
 * This function does not use the request state so it is safe to use
 * from any caller */
void sysdb_transaction_complete(struct tevent_req *subreq);


/* Sysdb initialization.
 * call this function *only* once to initialize the database and get
 * the sysdb ctx */
int sysdb_init(TALLOC_CTX *mem_ctx,
               struct tevent_context *ev,
               struct confdb_ctx *cdb,
               const char *alt_db_path,
               bool allow_upgrade,
               struct sysdb_ctx_list **_ctx_list);
/* used to initialize only one domain database.
 * Do NOT use if sysdb_init has already been called */
int sysdb_domain_init(TALLOC_CTX *mem_ctx,
                      struct tevent_context *ev,
                      struct sss_domain_info *domain,
                      const char *db_path,
                      struct sysdb_ctx **_ctx);

int sysdb_get_ctx_from_list(struct sysdb_ctx_list *ctx_list,
                            struct sss_domain_info *domain,
                            struct sysdb_ctx **_ctx);

/* FIXME: REMOVE */
typedef void (*sysdb_callback_t)(void *, int, struct ldb_result *);

/* functions to retrieve information from sysdb
 * These functions automatically starts an operation
 * therefore they cannot be called within a transaction */
int sysdb_getpwnam(TALLOC_CTX *mem_ctx,
                   struct sysdb_ctx *ctx,
                   struct sss_domain_info *domain,
                   const char *name,
                   sysdb_callback_t fn, void *ptr);

int sysdb_getpwuid(TALLOC_CTX *mem_ctx,
                   struct sysdb_ctx *ctx,
                   struct sss_domain_info *domain,
                   uid_t uid,
                   sysdb_callback_t fn, void *ptr);

int sysdb_enumpwent(TALLOC_CTX *mem_ctx,
                    struct sysdb_ctx *ctx,
                    struct sss_domain_info *domain,
                    const char *expression,
                    sysdb_callback_t fn, void *ptr);

int sysdb_getgrnam(TALLOC_CTX *mem_ctx,
                   struct sysdb_ctx *ctx,
                   struct sss_domain_info *domain,
                   const char *name,
                   sysdb_callback_t fn, void *ptr);

int sysdb_getgrgid(TALLOC_CTX *mem_ctx,
                   struct sysdb_ctx *ctx,
                   struct sss_domain_info *domain,
                   gid_t gid,
                   sysdb_callback_t fn, void *ptr);

int sysdb_enumgrent(TALLOC_CTX *mem_ctx,
                    struct sysdb_ctx *ctx,
                    struct sss_domain_info *domain,
                    sysdb_callback_t fn, void *ptr);

int sysdb_initgroups(TALLOC_CTX *mem_ctx,
                     struct sysdb_ctx *ctx,
                     struct sss_domain_info *domain,
                     const char *name,
                     sysdb_callback_t fn, void *ptr);

int sysdb_get_user_attr(TALLOC_CTX *mem_ctx,
                        struct sysdb_ctx *ctx,
                        struct sss_domain_info *domain,
                        const char *name,
                        const char **attributes,
                        sysdb_callback_t fn, void *ptr);


/* functions that modify the databse
 * they have to be called within a transaction
 * See sysdb_transaction_send()/_recv() */

/* Delete Entry */
struct tevent_req *sysdb_delete_entry_send(TALLOC_CTX *mem_ctx,
                                           struct tevent_context *ev,
                                           struct sysdb_handle *handle,
                                           struct ldb_dn *dn,
                                           bool ignore_not_found);
int sysdb_delete_entry_recv(struct tevent_req *req);


struct tevent_req *sysdb_delete_recursive_send(TALLOC_CTX *mem_ctx,
                                               struct tevent_context *ev,
                                               struct sysdb_handle *handle,
                                               struct ldb_dn *dn,
                                               bool ignore_not_found);
int sysdb_delete_recursive_recv(struct tevent_req *req);

/* Search Entry */
struct tevent_req *sysdb_search_entry_send(TALLOC_CTX *mem_ctx,
                                           struct tevent_context *ev,
                                           struct sysdb_handle *handle,
                                           struct ldb_dn *base_dn,
                                           int scope,
                                           const char *filter,
                                           const char **attrs);
int sysdb_search_entry_recv(struct tevent_req *req,
                            TALLOC_CTX *mem_ctx,
                            size_t *msgs_size,
                            struct ldb_message ***msgs);

/* Search User (by uid or name) */
struct tevent_req *sysdb_search_user_by_name_send(TALLOC_CTX *mem_ctx,
                                                  struct tevent_context *ev,
                                                  struct sysdb_ctx *sysdb,
                                                  struct sysdb_handle *handle,
                                                  struct sss_domain_info *domain,
                                                  const char *name,
                                                  const char **attrs);
struct tevent_req *sysdb_search_user_by_uid_send(TALLOC_CTX *mem_ctx,
                                                 struct tevent_context *ev,
                                                 struct sysdb_ctx *sysdb,
                                                 struct sysdb_handle *handle,
                                                 struct sss_domain_info *domain,
                                                 uid_t uid,
                                                 const char **attrs);
int sysdb_search_user_recv(struct tevent_req *req,
                           TALLOC_CTX *mem_ctx,
                           struct ldb_message **msg);

/* Search Group (gy gid or name) */
struct tevent_req *sysdb_search_group_by_name_send(TALLOC_CTX *mem_ctx,
                                                   struct tevent_context *ev,
                                                   struct sysdb_ctx *sysdb,
                                                   struct sysdb_handle *handle,
                                                   struct sss_domain_info *domain,
                                                   const char *name,
                                                   const char **attrs);
struct tevent_req *sysdb_search_group_by_gid_send(TALLOC_CTX *mem_ctx,
                                                  struct tevent_context *ev,
                                                  struct sysdb_ctx *sysdb,
                                                  struct sysdb_handle *handle,
                                                  struct sss_domain_info *domain,
                                                  gid_t gid,
                                                  const char **attrs);
int sysdb_search_group_recv(struct tevent_req *req,
                            TALLOC_CTX *mem_ctx,
                            struct ldb_message **msg);

/* Replace entry attrs */
struct tevent_req *sysdb_set_entry_attr_send(TALLOC_CTX *mem_ctx,
                                             struct tevent_context *ev,
                                             struct sysdb_handle *handle,
                                             struct ldb_dn *entry_dn,
                                             struct sysdb_attrs *attrs,
                                             int mod_op);
int sysdb_set_entry_attr_recv(struct tevent_req *req);

/* Replace user attrs */
struct tevent_req *sysdb_set_user_attr_send(TALLOC_CTX *mem_ctx,
                                            struct tevent_context *ev,
                                            struct sysdb_handle *handle,
                                            struct sss_domain_info *domain,
                                            const char *name,
                                            struct sysdb_attrs *attrs,
                                            int mod_op);
int sysdb_set_user_attr_recv(struct tevent_req *req);

/* Replace group attrs */
struct tevent_req *sysdb_set_group_attr_send(TALLOC_CTX *mem_ctx,
                                             struct tevent_context *ev,
                                             struct sysdb_handle *handle,
                                             struct sss_domain_info *domain,
                                             const char *name,
                                             struct sysdb_attrs *attrs,
                                             int mod_op);
int sysdb_set_group_attr_recv(struct tevent_req *req);

/* Allocate a new id */
struct tevent_req *sysdb_get_new_id_send(TALLOC_CTX *mem_ctx,
                                         struct tevent_context *ev,
                                         struct sysdb_handle *handle,
                                         struct sss_domain_info *domain);
int sysdb_get_new_id_recv(struct tevent_req *req, uint32_t *id);

/* Add user (only basic attrs and w/o checks) */
struct tevent_req *sysdb_add_basic_user_send(TALLOC_CTX *mem_ctx,
                                             struct tevent_context *ev,
                                             struct sysdb_handle *handle,
                                             struct sss_domain_info *domain,
                                             const char *name,
                                             uid_t uid, gid_t gid,
                                             const char *gecos,
                                             const char *homedir,
                                             const char *shell);
int sysdb_add_basic_user_recv(struct tevent_req *req);

/* Add fake (expired) user */
struct tevent_req *sysdb_add_fake_user_send(TALLOC_CTX *mem_ctx,
                                            struct tevent_context *ev,
                                            struct sysdb_handle *handle,
                                            struct sss_domain_info *domain,
                                            const char *name);
int sysdb_add_fake_user_recv(struct tevent_req *req);

/* Add user (all checks) */
struct tevent_req *sysdb_add_user_send(TALLOC_CTX *mem_ctx,
                                       struct tevent_context *ev,
                                       struct sysdb_handle *handle,
                                       struct sss_domain_info *domain,
                                       const char *name,
                                       uid_t uid, gid_t gid,
                                       const char *gecos,
                                       const char *homedir,
                                       const char *shell,
                                       struct sysdb_attrs *attrs,
                                       int cache_timeout);
int sysdb_add_user_recv(struct tevent_req *req);

/* Add group (only basic attrs and w/o checks) */
struct tevent_req *sysdb_add_basic_group_send(TALLOC_CTX *mem_ctx,
                                              struct tevent_context *ev,
                                              struct sysdb_handle *handle,
                                              struct sss_domain_info *domain,
                                              const char *name, gid_t gid);
int sysdb_add_basic_group_recv(struct tevent_req *req);

/* Add group (all checks) */
struct tevent_req *sysdb_add_group_send(TALLOC_CTX *mem_ctx,
                                        struct tevent_context *ev,
                                        struct sysdb_handle *handle,
                                        struct sss_domain_info *domain,
                                        const char *name, gid_t gid,
                                        struct sysdb_attrs *attrs,
                                        int cache_timeout);
int sysdb_add_group_recv(struct tevent_req *req);

/* Add a incomplete, expired group */
struct tevent_req *sysdb_add_incomplete_group_send(TALLOC_CTX *mem_ctx,
                                             struct tevent_context *ev,
                                             struct sysdb_handle *handle,
                                             struct sss_domain_info *domain,
                                             const char *name, gid_t gid);
int sysdb_add_incomplete_group_recv(struct tevent_req *req);

/* mod_op must be either LDB_FLAG_MOD_ADD or LDB_FLAG_MOD_DELETE */
struct tevent_req *sysdb_mod_group_member_send(TALLOC_CTX *mem_ctx,
                                               struct tevent_context *ev,
                                               struct sysdb_handle *handle,
                                               struct ldb_dn *member_dn,
                                               struct ldb_dn *group_dn,
                                               int mod_op);
int sysdb_mod_group_member_recv(struct tevent_req *req);

int sysdb_set_group_gid(struct sysdb_handle *handle,
                        struct sss_domain_info *domain,
                        const char *name, gid_t gid,
                        sysdb_callback_t fn, void *pvt);

struct tevent_req *sysdb_store_user_send(TALLOC_CTX *mem_ctx,
                                         struct tevent_context *ev,
                                         struct sysdb_handle *handle,
                                         struct sss_domain_info *domain,
                                         const char *name,
                                         const char *pwd,
                                         uid_t uid, gid_t gid,
                                         const char *gecos,
                                         const char *homedir,
                                         const char *shell,
                                         struct sysdb_attrs *attrs,
                                         uint64_t cache_timeout);
int sysdb_store_user_recv(struct tevent_req *req);

struct tevent_req *sysdb_store_group_send(TALLOC_CTX *mem_ctx,
                                          struct tevent_context *ev,
                                          struct sysdb_handle *handle,
                                          struct sss_domain_info *domain,
                                          const char *name,
                                          gid_t gid,
                                          struct sysdb_attrs *attrs,
                                          uint64_t cache_timeout);
int sysdb_store_group_recv(struct tevent_req *req);

enum sysdb_member_type {
    SYSDB_MEMBER_USER,
    SYSDB_MEMBER_GROUP
};

struct tevent_req *sysdb_add_group_member_send(TALLOC_CTX *mem_ctx,
                                               struct tevent_context *ev,
                                               struct sysdb_handle *handle,
                                               struct sss_domain_info *domain,
                                               const char *group,
                                               const char *member,
                                               enum sysdb_member_type type);
int sysdb_add_group_member_recv(struct tevent_req *req);

struct tevent_req *sysdb_remove_group_member_send(TALLOC_CTX *mem_ctx,
                                                  struct tevent_context *ev,
                                                  struct sysdb_handle *handle,
                                                  struct sss_domain_info *domain,
                                                  const char *group,
                                                  const char *member,
                                                  enum sysdb_member_type type);
int sysdb_remove_group_member_recv(struct tevent_req *req);


struct tevent_req *sysdb_update_members_send(TALLOC_CTX *mem_ctx,
                                             struct tevent_context *ev,
                                             struct sysdb_handle *handle,
                                             struct sss_domain_info *domain,
                                             const char *member,
                                             enum sysdb_member_type type,
                                             char **add_groups,
                                             char **del_groups);
errno_t sysdb_update_members_recv(struct tevent_req *req);

/* Password caching function.
 * If you are in a transaction ignore sysdb and pass in the handle.
 * If you are not in a transaction pass NULL in handle and provide sysdb,
 * in this case a transaction will be automatically started and the
 * function will be completely wrapped in it's own sysdb transaction */
struct tevent_req *sysdb_cache_password_send(TALLOC_CTX *mem_ctx,
                                             struct tevent_context *ev,
                                             struct sysdb_ctx *sysdb,
                                             struct sysdb_handle *handle,
                                             struct sss_domain_info *domain,
                                             const char *username,
                                             const char *password);
int sysdb_cache_password_recv(struct tevent_req *req);


errno_t check_failed_login_attempts(TALLOC_CTX *mem_ctx, struct confdb_ctx *cdb,
                                    struct ldb_message *ldb_msg,
                                    uint32_t *failed_login_attempts,
                                    time_t *delayed_until);
struct tevent_req *sysdb_cache_auth_send(TALLOC_CTX *mem_ctx,
                                         struct tevent_context *ev,
                                         struct sysdb_ctx *sysdb,
                                         struct sss_domain_info *domain,
                                         const char *name,
                                         const uint8_t *authtok,
                                         size_t authtok_size,
                                         struct confdb_ctx *cdb,
                                         bool just_check);
int sysdb_cache_auth_recv(struct tevent_req *req, time_t *expire_date,
                          time_t *delayed_until);

struct tevent_req *sysdb_store_custom_send(TALLOC_CTX *mem_ctx,
                                         struct tevent_context *ev,
                                         struct sysdb_handle *handle,
                                         struct sss_domain_info *domain,
                                         const char *object_name,
                                         const char *subtree_name,
                                         struct sysdb_attrs *attrs);
int sysdb_store_custom_recv(struct tevent_req *req);

struct tevent_req *sysdb_search_custom_send(TALLOC_CTX *mem_ctx,
                                            struct tevent_context *ev,
                                            struct sysdb_ctx *sysdb,
                                            struct sysdb_handle *handle,
                                            struct sss_domain_info *domain,
                                            const char *filter,
                                            const char *subtree_name,
                                            const char **attrs);
struct tevent_req *sysdb_search_custom_by_name_send(TALLOC_CTX *mem_ctx,
                                                    struct tevent_context *ev,
                                                    struct sysdb_ctx *sysdb,
                                                    struct sysdb_handle *handle,
                                                    struct sss_domain_info *domain,
                                                    const char *object_name,
                                                    const char *subtree_name,
                                                    const char **attrs);
int sysdb_search_custom_recv(struct tevent_req *req,
                              TALLOC_CTX *mem_ctx,
                              size_t *msgs_count,
                              struct ldb_message ***msg);

struct tevent_req *sysdb_delete_custom_send(TALLOC_CTX *mem_ctx,
                                             struct tevent_context *ev,
                                             struct sysdb_handle *handle,
                                             struct sss_domain_info *domain,
                                             const char *object_name,
                                             const char *subtree_name);
int sysdb_delete_custom_recv(struct tevent_req *req);

struct tevent_req *sysdb_asq_search_send(TALLOC_CTX *mem_ctx,
                                         struct tevent_context *ev,
                                         struct sysdb_ctx *sysdb,
                                         struct sysdb_handle *handle,
                                         struct sss_domain_info *domain,
                                         struct ldb_dn *base_dn,
                                         const char *expression,
                                         const char *asq_attribute,
                                         const char **attrs);
int sysdb_asq_search_recv(struct tevent_req *req, TALLOC_CTX *mem_ctx,
                          size_t *msgs_count, struct ldb_message ***msgs);

struct tevent_req *sysdb_search_users_send(TALLOC_CTX *mem_ctx,
                                           struct tevent_context *ev,
                                           struct sysdb_ctx *sysdb,
                                           struct sysdb_handle *handle,
                                           struct sss_domain_info *domain,
                                           const char *sub_filter,
                                           const char **attrs);
int sysdb_search_users_recv(struct tevent_req *req, TALLOC_CTX *mem_ctx,
                            size_t *msgs_count, struct ldb_message ***msgs);

struct tevent_req *sysdb_delete_user_send(TALLOC_CTX *mem_ctx,
                                          struct tevent_context *ev,
                                          struct sysdb_ctx *sysdb,
                                          struct sysdb_handle *handle,
                                          struct sss_domain_info *domain,
                                          const char *name, uid_t uid);
int sysdb_delete_user_recv(struct tevent_req *req);

struct tevent_req *sysdb_search_groups_send(TALLOC_CTX *mem_ctx,
                                            struct tevent_context *ev,
                                            struct sysdb_ctx *sysdb,
                                            struct sysdb_handle *handle,
                                            struct sss_domain_info *domain,
                                            const char *sub_filter,
                                            const char **attrs);
int sysdb_search_groups_recv(struct tevent_req *req, TALLOC_CTX *mem_ctx,
                             size_t *msgs_count, struct ldb_message ***msgs);

struct tevent_req *sysdb_delete_group_send(TALLOC_CTX *mem_ctx,
                                           struct tevent_context *ev,
                                           struct sysdb_ctx *sysdb,
                                           struct sysdb_handle *handle,
                                           struct sss_domain_info *domain,
                                           const char *name, gid_t gid);
int sysdb_delete_group_recv(struct tevent_req *req);

errno_t sysdb_attrs_to_list(TALLOC_CTX *memctx,
                            struct sysdb_attrs **attrs,
                            int attr_count,
                            const char *attr_name,
                            char ***_list);

#endif /* __SYS_DB_H__ */
